package sysctl

import (
	"errors"
	"strconv"

	"github.com/YarBurArt/kishirika/internal/baseline"
	"github.com/YarBurArt/kishirika/internal/check"
	"github.com/YarBurArt/kishirika/internal/host"
)

const Family = "sysctl"

func Evaluate(checks []baseline.SysctlCheck, r host.Reader) []check.Finding {
	return check.MapAll(checks, func(c baseline.SysctlCheck) check.Finding {
		return evaluateOne(c, r)
	})
}

func evaluateOne(c baseline.SysctlCheck, r host.Reader) check.Finding {
	f := check.Finding{
		Family:    Family,
		Key:       c.Key,
		Expect:    c.Expect.String(),
		Severity:  c.Severity,
		Rationale: c.Rationale,
	}

	raw, err := r.Sysctl(c.Key)
	if err != nil {
		f.Status = check.Skip
		f.Reason = reason(err)
		return f
	}
	f.Actual = raw

	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		f.Status = check.Skip
		f.Reason = "unparseable"
		return f
	}

	if c.Expect.Met(value) {
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
