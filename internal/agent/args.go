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

// intArg reads a bounded integer argument, clamped to [1, maximum]. Zero
// maximum means uncapped. Absent or zero means def — schemas require every
// property (strict mode), so 0 is the documented "use the default" sentinel.
// A negative value is rejected.
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
	if n < 0 {
		return 0, fmt.Errorf("argument %q must not be negative", name)
	}
	if n == 0 {
		return def, nil
	}
	if maximum > 0 && n > maximum {
		n = maximum
	}
	return n, nil
}
