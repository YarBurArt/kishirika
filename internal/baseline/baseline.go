package baseline

import (
	"embed"
	"encoding/json"
	"fmt"

	"github.com/YarBurArt/kishirika/internal/check"
)

//go:embed data/*.json
var files embed.FS

type SysctlCheck struct {
	Key       string          `json:"key"`
	Expect    check.Predicate `json:"expect"`
	Severity  check.Severity  `json:"severity"`
	Rationale string          `json:"rationale"`
}

type SELinuxCheck struct {
	Key       string         `json:"key"`
	Expect    string         `json:"expect"`
	Severity  check.Severity `json:"severity"`
	Rationale string         `json:"rationale"`
}

func LoadSysctl() ([]SysctlCheck, error) {
	var out struct {
		Checks []SysctlCheck `json:"checks"`
	}
	if err := load("sysctl.json", &out); err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(out.Checks))
	for i, c := range out.Checks {
		switch {
		case c.Key == "":
			return nil, fmt.Errorf("sysctl.json check %d: key is required", i)
		case seen[c.Key]:
			return nil, fmt.Errorf("sysctl.json: duplicate key %q", c.Key)
		case !c.Severity.Valid():
			return nil, fmt.Errorf("%s: unknown severity %q", c.Key, c.Severity)
		}
		if err := c.Expect.Validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", c.Key, err)
		}
		seen[c.Key] = true
	}
	return out.Checks, nil
}

func LoadSELinux() ([]SELinuxCheck, error) {
	var out struct {
		Checks []SELinuxCheck `json:"checks"`
	}
	if err := load("selinux.json", &out); err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(out.Checks))
	for i, c := range out.Checks {
		switch {
		case c.Key == "":
			return nil, fmt.Errorf("selinux.json check %d: key is required", i)
		case seen[c.Key]:
			return nil, fmt.Errorf("selinux.json: duplicate key %q", c.Key)
		case !c.Severity.Valid():
			return nil, fmt.Errorf("%s: unknown severity %q", c.Key, c.Severity)
		case c.Expect != "on" && c.Expect != "off":
			return nil, fmt.Errorf("%s: expect must be on or off, got %q", c.Key, c.Expect)
		}
		seen[c.Key] = true
	}
	return out.Checks, nil
}

func load[T any](name string, dst *T) error {
	raw, err := files.ReadFile("data/" + name)
	if err != nil {
		return fmt.Errorf("read %s: %w", name, err)
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return fmt.Errorf("parse %s: %w", name, err)
	}
	return nil
}
