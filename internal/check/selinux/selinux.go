package selinux

import (
	"errors"

	"github.com/YarBurArt/kishirika/internal/baseline"
	"github.com/YarBurArt/kishirika/internal/check"
	"github.com/YarBurArt/kishirika/internal/host"
)

const Family = "selinux"

func Evaluate(checks []baseline.SELinuxCheck, r host.Reader) []check.Finding {
	return check.MapAll(checks, func(c baseline.SELinuxCheck) check.Finding {
		return evaluateOne(c, r)
	})
}

func evaluateOne(c baseline.SELinuxCheck, r host.Reader) check.Finding {
	f := check.Finding{
		Family:    Family,
		Key:       c.Key,
		Expect:    c.Expect,
		Severity:  c.Severity,
		Rationale: c.Rationale,
	}

	value, err := r.Boolean(c.Key)
	if err != nil {
		f.Status = check.Skip
		f.Reason = reason(err)
		return f
	}

	if value {
		f.Actual = "on"
	} else {
		f.Actual = "off"
	}

	if f.Actual == c.Expect {
		f.Status = check.Pass
	} else {
		f.Status = check.Fail
	}
	return f
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
