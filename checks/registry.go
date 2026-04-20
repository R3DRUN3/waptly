package checks

import "net/http"

// Result holds the output of a single check against a target.
type Result struct {
	CheckName string         `json:"check"`
	Passed    bool           `json:"passed"`
	Details   map[string]any `json:"details,omitempty"`
	Error     string         `json:"error,omitempty"`
}

// Check is the interface every module must implement.
type Check interface {
	Name() string
	Run(target string, resp *http.Response) Result
}

// registry holds all registered checks.
var registry []Check

// Register adds a check to the global registry (called from init()).
func Register(c Check) {
	registry = append(registry, c)
}

// All returns the full list of registered checks.
func All() []Check {
	return registry
}
