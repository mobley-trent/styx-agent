package containerlayer

import (
	"context"
	"strings"
	"testing"
)

// TestDockerEnsureImageRequiresRef guards the boundary input: no image name is
// a programming error, not something to hand to the daemon.
func TestDockerEnsureImageRequiresRef(t *testing.T) {
	// A zero-value Docker has no client; the ref check must run first.
	d := &Docker{}
	for _, ref := range []string{"", "   ", "\t"} {
		if err := d.EnsureImage(context.Background(), ref); err == nil {
			t.Errorf("EnsureImage(%q) = nil error, want a required-image error", ref)
		} else if !strings.Contains(err.Error(), "image is required") {
			t.Errorf("EnsureImage(%q) = %v, want it to name the missing image", ref, err)
		}
	}
}
