package selinux

import (
	"errors"

	"github.com/YarBurArt/kishirika/internal/baseline"
	"github.com/YarBurArt/kishirika/internal/check"
	"github.com/YarBurArt/kishirika/internal/host"
)

const Family = "selinux"

// The +2 keeps the state pair from reallocating the boolean findings.
func Evaluate(checks []baseline.SELinuxCheck, r host.Reader, state *host.SELinux) []check.Finding {
	findings := make([]check.Finding, 0, len(checks)+2)
	findings = append(findings, stateFindings(state)...)

	return append(findings, check.MapAll(checks, func(c baseline.SELinuxCheck) check.Finding {
		return evaluateOne(c, r)
	})...)
}

func evaluateOne(c baseline.SELinuxCheck, r host.Reader) check.Finding {
	f := check.Finding{
		Family:    Family,
		Key:       c.Key,
		Expect:    c.Expect,
		Severity:  c.Severity,
		Rationale: c.Rationale,
	}

	current, pending, err := r.Boolean(c.Key)
	if err != nil {
		f.Status = check.Skip
		f.Reason = reason(err)
		return f
	}

	f.Actual = onOff(current)
	switch {
	case f.Actual != c.Expect:
		f.Status = check.Fail
	case pending != current:
		// flipped with setsebool and no -P, so the policy still holds the old value
		f.Status = check.Fail
		f.Reason = "reverts at the next policy load"
	default:
		f.Status = check.Pass
	}
	return f
}

// What no boolean file holds: the runtime mode against the config, and the
// policy name the next boot would load.
func stateFindings(s *host.SELinux) []check.Finding {
	if s == nil {
		return nil
	}

	mode := check.Finding{
		Family:    Family,
		Key:       "mode",
		Expect:    s.Config,
		Actual:    s.Mode,
		Severity:  check.High,
		Rationale: "A permissive kernel lets an exploit through whatever the policy says.",
	}
	switch {
	case s.Config == "":
		mode.Status = check.Skip
		mode.Reason = "no /etc/selinux/config"
	case s.Mode == s.Config:
		mode.Status = check.Pass
	default:
		mode.Status = check.Fail
	}

	policy := check.Finding{
		Family:    Family,
		Key:       "policy",
		Expect:    "set",
		Actual:    s.Policy,
		Severity:  check.Medium,
		Rationale: "Without a policy name the next boot loads no policy at all.",
	}
	if s.Policy == "" {
		policy.Status = check.Fail
		policy.Reason = "SELINUXTYPE missing"
	} else {
		policy.Status = check.Pass
	}

	return []check.Finding{mode, policy}
}

func onOff(value bool) string {
	if value {
		return "on"
	}
	return "off"
}

func reason(err error) string {
	switch {
	case errors.Is(err, host.ErrAbsent):
		return "absent"
	case errors.Is(err, host.ErrDenied):
		return "permission-denied"
	default:
		return "unreadable"
	}
}
