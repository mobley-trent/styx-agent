package containerlayer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
)

// defaultImagePullTimeout bounds a missing-image pull. A registry that accepts
// the connection but never streams would otherwise hang the first exec forever;
// a stalled pull fails with a clear error instead. The session ctx can still
// cancel sooner (Ctrl+C in the TUI).
const defaultImagePullTimeout = 5 * time.Minute

// Docker is the production Runtime: the official Docker SDK for Go, pointed at
// the local daemon (or DOCKER_HOST / an injected endpoint).
//
// The runtime is deliberately the only place that talks to Docker, so the
// session orchestration above it is testable against a fake and no other
// package learns the mechanism (§2).
type Docker struct {
	cli *client.Client
}

// DockerOption configures a Docker runtime.
type DockerOption func(*dockerConfig)

type dockerConfig struct {
	host string
}

// WithDockerHost overrides the daemon endpoint. Without it the SDK reads
// DOCKER_HOST and the platform default socket.
func WithDockerHost(host string) DockerOption {
	return func(c *dockerConfig) { c.host = host }
}

// NewDocker builds a Docker runtime. It does not contact the daemon; call
// Available to probe it.
func NewDocker(opts ...DockerOption) (*Docker, error) {
	var cfg dockerConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	clientOpts := []client.Opt{client.WithAPIVersionNegotiation()}
	if cfg.host != "" {
		clientOpts = append(clientOpts, client.WithHost(cfg.host))
	} else {
		clientOpts = append(clientOpts, client.FromEnv)
	}
	cli, err := client.NewClientWithOpts(clientOpts...)
	if err != nil {
		return nil, fmt.Errorf("containerlayer: docker client: %w", err)
	}
	return &Docker{cli: cli}, nil
}

// Available implements Runtime.
func (d *Docker) Available(ctx context.Context) error {
	if _, err := d.cli.Ping(ctx); err != nil {
		return fmt.Errorf("containerlayer: docker daemon is not reachable: %w", err)
	}
	return nil
}

// EnsureImage implements ImageEnsurer. It inspects the local image and pulls it
// only when absent, so an already-present image costs no network. The pull is
// bounded so an unresponsive registry cannot hang the exec tools indefinitely.
func (d *Docker) EnsureImage(ctx context.Context, ref string) error {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return errors.New("containerlayer: ensure image: image is required")
	}
	if _, err := d.cli.ImageInspect(ctx, ref); err == nil {
		return nil
	} else if !cerrdefs.IsNotFound(err) {
		return fmt.Errorf("containerlayer: inspect image %s: %w", ref, err)
	}

	ctx, cancel := context.WithTimeout(ctx, defaultImagePullTimeout)
	defer cancel()
	rc, err := d.cli.ImagePull(ctx, ref, image.PullOptions{})
	if err != nil {
		return fmt.Errorf("containerlayer: pull image %s: %w", ref, err)
	}
	defer func() { _ = rc.Close() }()
	// The pull stream is progress JSON; draining it is what completes the
	// pull and surfaces a mid-stream error.
	if _, err := io.Copy(io.Discard, rc); err != nil {
		return fmt.Errorf("containerlayer: pull image %s: %w", ref, err)
	}
	return nil
}

// CreateNetwork implements Runtime.
func (d *Docker) CreateNetwork(ctx context.Context, req NetworkRequest) (string, error) {
	opts := network.CreateOptions{
		Driver:   "bridge",
		Internal: req.Internal,
		Options:  map[string]string{"com.docker.network.bridge.name": req.Bridge},
	}
	if req.Subnet != "" {
		opts.IPAM = &network.IPAM{
			Driver: "default",
			Config: []network.IPAMConfig{{Subnet: req.Subnet, Gateway: req.Gateway}},
		}
	}
	resp, err := d.cli.NetworkCreate(ctx, req.Name, opts)
	if err != nil {
		return "", fmt.Errorf("containerlayer: create network %s: %w", req.Name, err)
	}
	return resp.ID, nil
}

// RemoveNetwork implements Runtime.
func (d *Docker) RemoveNetwork(ctx context.Context, id string) error {
	if err := d.cli.NetworkRemove(ctx, id); err != nil {
		// An already-gone network is a clean teardown.
		if cerrdefs.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("containerlayer: remove network %s: %w", id, err)
	}
	return nil
}

// CreateContainer implements Runtime.
func (d *Docker) CreateContainer(ctx context.Context, spec ContainerSpec) (string, error) {
	if err := validateContainerSpec(spec); err != nil {
		return "", err
	}
	resp, err := d.cli.ContainerCreate(ctx,
		&container.Config{
			Image:      spec.Image,
			Cmd:        spec.Cmd,
			Env:        spec.Env,
			WorkingDir: spec.WorkingDir,
		},
		&container.HostConfig{
			NetworkMode: container.NetworkMode(spec.NetworkID),
			Binds:       spec.Binds,
			DNS:         spec.DNS,
		},
		nil, nil, spec.Name,
	)
	if err != nil {
		return "", fmt.Errorf("containerlayer: create container %s: %w", spec.Name, err)
	}
	return resp.ID, nil
}

// StartContainer implements Runtime.
func (d *Docker) StartContainer(ctx context.Context, id string) error {
	if err := d.cli.ContainerStart(ctx, id, container.StartOptions{}); err != nil {
		return fmt.Errorf("containerlayer: start container %s: %w", id, err)
	}
	return nil
}

// Exec implements Runtime. It demultiplexes the Docker stream into stdout and
// stderr and reports the exec's exit code.
func (d *Docker) Exec(ctx context.Context, id string, req ExecRequest) (ExecResult, error) {
	created, err := d.cli.ContainerExecCreate(ctx, id, container.ExecOptions{
		Cmd:          req.Cmd,
		Env:          req.Env,
		WorkingDir:   req.WorkDir,
		AttachStdout: true,
		AttachStderr: true,
	})
	if err != nil {
		return ExecResult{}, fmt.Errorf("containerlayer: create exec in %s: %w", id, err)
	}
	attach, err := d.cli.ContainerExecAttach(ctx, created.ID, container.ExecAttachOptions{})
	if err != nil {
		return ExecResult{}, fmt.Errorf("containerlayer: attach exec in %s: %w", id, err)
	}
	defer attach.Close()

	var stdout, stderr bytes.Buffer
	if _, err := stdcopy.StdCopy(&stdout, &stderr, attach.Reader); err != nil && !errors.Is(err, io.EOF) {
		return ExecResult{}, fmt.Errorf("containerlayer: read exec output in %s: %w", id, err)
	}
	inspect, err := d.cli.ContainerExecInspect(ctx, created.ID)
	if err != nil {
		return ExecResult{}, fmt.Errorf("containerlayer: inspect exec in %s: %w", id, err)
	}
	return ExecResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: inspect.ExitCode,
	}, nil
}

// RemoveContainer implements Runtime.
func (d *Docker) RemoveContainer(ctx context.Context, id string) error {
	if err := d.cli.ContainerRemove(ctx, id, container.RemoveOptions{Force: true, RemoveVolumes: true}); err != nil {
		if cerrdefs.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("containerlayer: remove container %s: %w", id, err)
	}
	return nil
}

// Close implements Runtime.
func (d *Docker) Close() error {
	if err := d.cli.Close(); err != nil {
		return fmt.Errorf("containerlayer: close docker client: %w", err)
	}
	return nil
}

// compile-time assertion: the SDK runtime satisfies Runtime.
var _ Runtime = (*Docker)(nil)

// and it can make the pinned session image available.
var _ ImageEnsurer = (*Docker)(nil)
