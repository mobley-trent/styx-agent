package agent

import (
	"context"
	"strings"
	"testing"
)

func TestReadFileToolConfinedToWorkspace(t *testing.T) {
	dir := workspace(t, map[string]string{
		"sub/nested.txt": "nested contents\n",
		"top.txt":        "top contents\n",
	})
	tool := ReadFileTool(dir)

	tests := []struct {
		name    string
		args    map[string]any
		want    string
		wantErr string
	}{
		{name: "relative path", args: map[string]any{"path": "top.txt"}, want: "top contents\n"},
		{name: "nested relative path", args: map[string]any{"path": "sub/nested.txt"}, want: "nested contents\n"},
		{name: "absolute path inside", args: map[string]any{"path": dir + "/top.txt"}, want: "top contents\n"},
		{name: "parent escape", args: map[string]any{"path": "../secrets"}, wantErr: "outside the workspace"},
		{name: "deep escape", args: map[string]any{"path": "sub/../../secrets"}, wantErr: "outside the workspace"},
		{name: "directory", args: map[string]any{"path": "sub"}, wantErr: "directory"},
		{name: "missing argument", args: map[string]any{}, wantErr: "path"},
		{name: "empty argument", args: map[string]any{"path": ""}, wantErr: "path"},
		{name: "wrong type", args: map[string]any{"path": 3}, wantErr: "string"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tool.Handler(context.Background(), tt.args)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("Handler() = %q, want an error containing %q", got, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Handler() error = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Handler() = %v, want nil", err)
			}
			if got != tt.want {
				t.Errorf("Handler() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestReadFileDescriptor(t *testing.T) {
	desc := ReadFileTool("/tmp").Descriptor()
	if desc.Name != "read_file" || !desc.Strict {
		t.Errorf("descriptor = %+v, want read_file in strict mode", desc)
	}
	if !strings.Contains(string(desc.Parameters), `"required"`) {
		t.Errorf("descriptor schema lacks required properties: %s", desc.Parameters)
	}
}

func TestRegistryRejectsBadTools(t *testing.T) {
	if _, err := NewRegistry(Tool{Name: "", Handler: func(context.Context, map[string]any) (string, error) { return "", nil }}); err == nil {
		t.Error("NewRegistry(empty name) = nil error, want an error")
	}
	if _, err := NewRegistry(Tool{Name: "x"}); err == nil {
		t.Error("NewRegistry(no handler) = nil error, want an error")
	}
	handler := func(context.Context, map[string]any) (string, error) { return "", nil }
	if _, err := NewRegistry(Tool{Name: "x", Handler: handler}, Tool{Name: "x", Handler: handler}); err == nil {
		t.Error("NewRegistry(duplicate) = nil error, want an error")
	}
}

func TestReadFileToolCapsLargeFiles(t *testing.T) {
	big := strings.Repeat("a", maxReadBytes+1024)
	dir := workspace(t, map[string]string{"big.txt": big})
	got, err := ReadFileTool(dir).Handler(context.Background(), map[string]any{"path": "big.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) > maxReadBytes+200 {
		t.Errorf("read %d bytes, want the read capped near %d", len(got), maxReadBytes)
	}
	if !strings.Contains(got, "larger than") {
		t.Error("capped read lacks an explanation marker")
	}
}
