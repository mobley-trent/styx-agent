package agent

import (
	"context"
	"encoding/json"
	"errors"
)

// Executor runs the exec tools' commands in the session container (§5.2). It
// is the seam that keeps `agent` unaware of the container mechanism: the
// containerlayer session implements it, tests substitute a fake, and the exec
// tools never touch the host directly.
type Executor interface {
	// Shell runs a shell command in the session container.
	Shell(ctx context.Context, command string) (string, error)
	// Code runs a snippet in a language runtime present in the container.
	Code(ctx context.Context, lang, code string) (string, error)
}

// bashSchema is the `bash` descriptor's JSON Schema (strict mode: every
// property is declared and additionalProperties is false).
const bashSchema = `{
  "type": "object",
  "properties": {
    "command": {
      "type": "string",
      "description": "Shell command to run in the session container, e.g. \"go test ./...\" or \"ls -la\"."
    }
  },
  "required": ["command"],
  "additionalProperties": false
}`

// codeExecSchema is the `code_exec` descriptor's JSON Schema. python3 is the
// first and default language.
const codeExecSchema = `{
  "type": "object",
  "properties": {
    "lang": {
      "type": "string",
      "description": "Language runtime to use. python3 (default), sh, node, ruby, perl, or go."
    },
    "code": {
      "type": "string",
      "description": "The snippet to run in the session container."
    }
  },
  "required": ["lang", "code"],
  "additionalProperties": false
}`

// BashTool is the §5.1 `bash` tool: shell commands, container-only, so the
// container's egress rules are the network boundary. It carries no network
// targets of its own — the egress layer, not the parameter check, is what
// bounds it.
func BashTool(exec Executor) Tool {
	return Tool{
		Name:        "bash",
		Description: "Run a shell command in the session container. Use for builds, tests, and CLI tooling; the container's network egress is limited to the engagement scope.",
		Parameters:  json.RawMessage(bashSchema),
		Handler: func(ctx context.Context, args map[string]any) (string, error) {
			command, err := stringArg(args, "command")
			if err != nil {
				return "", err
			}
			if exec == nil {
				return "", errors.New("no session container is available to run bash")
			}
			return exec.Shell(ctx, command)
		},
	}
}

// CodeExecTool is the §5.1 `code_exec` tool: a snippet in a language runtime
// present in the container, selected by the `lang` parameter.
func CodeExecTool(exec Executor) Tool {
	return Tool{
		Name:        "code_exec",
		Description: "Run a code snippet in the session container. Set lang to python3 (default), sh, node, ruby, perl, or go. Use for data processing and quick scripts.",
		Parameters:  json.RawMessage(codeExecSchema),
		Handler: func(ctx context.Context, args map[string]any) (string, error) {
			lang, err := stringArg(args, "lang")
			if err != nil {
				return "", err
			}
			code, err := stringArg(args, "code")
			if err != nil {
				return "", err
			}
			if exec == nil {
				return "", errors.New("no session container is available to run code_exec")
			}
			return exec.Code(ctx, lang, code)
		},
	}
}
