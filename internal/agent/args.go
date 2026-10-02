package agent

import "fmt"

// stringArg reads a required string argument.
func stringArg(args map[string]any, name string) (string, error) {
	v, ok := args[name]
	if !ok {
		return "", fmt.Errorf("missing required argument %q", name)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("argument %q must be a string", name)
	}
	return s, nil
}

// optionalStringArg reads a string argument, returning def when it is absent
// or empty.
func optionalStringArg(args map[string]any, name, def string) (string, error) {
	v, ok := args[name]
	if !ok {
		return def, nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("argument %q must be a string", name)
	}
	if s == "" {
		return def, nil
	}
	return s, nil
}

// boolArg reads an optional boolean argument, defaulting to false.
func boolArg(args map[string]any, name string) (bool, error) {
	v, ok := args[name]
	if !ok {
		return false, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("argument %q must be a boolean", name)
	}
	return b, nil
}

// intArg reads an optional positive integer argument, clamped to [1,
// maximum]. Zero maximum means uncapped; absent means def.
func intArg(args map[string]any, name string, def, maximum int) (int, error) {
	v, ok := args[name]
	if !ok {
		return def, nil
	}
	var n int
	switch v := v.(type) {
	case int:
		n = v
	case int64:
		n = int(v)
	case float64:
		n = int(v)
		if float64(n) != v {
			return 0, fmt.Errorf("argument %q must be an integer", name)
		}
	default:
		return 0, fmt.Errorf("argument %q must be an integer", name)
	}
	if n <= 0 {
		return 0, fmt.Errorf("argument %q must be positive", name)
	}
	if maximum > 0 && n > maximum {
		n = maximum
	}
	return n, nil
}
