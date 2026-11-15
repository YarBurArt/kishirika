// Package baseline holds the check tables. data/*.json is the source of truth;
// go generate compiles it into data_gen.go, so a run decodes nothing.
package baseline

import (
	"github.com/YarBurArt/kishirika/internal/check"
)

//go:generate go run ./gen

type SysctlCheck struct {
	Key       string
	Expect    check.Predicate
	Severity  check.Severity
	Rationale string
}

type SELinuxCheck struct {
	Key       string
	Expect    string
	Severity  check.Severity
	Rationale string
}

func Sysctl() []SysctlCheck {
	return sysctlChecks
}

func SELinux() []SELinuxCheck {
	return selinuxChecks
}

// the generated tables spell their predicates out with these
func eq(value int64) check.Predicate {
	return check.Predicate{Eq: &value}
}

func gte(value int64) check.Predicate {
	return check.Predicate{Gte: &value}
}
