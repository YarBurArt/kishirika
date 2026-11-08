package sysctl

import (
	"testing"

	"github.com/YarBurArt/kishirika/internal/baseline"
	"github.com/YarBurArt/kishirika/internal/check"
	"github.com/YarBurArt/kishirika/internal/host"
)

type fakeReader map[string]string

func (f fakeReader) Sysctl(key string) (string, error) {
	value, ok := f[key]
	if !ok {
		return "", host.ErrAbsent
	}
	return value, nil
}

func (f fakeReader) Boolean(string) (bool, error) { return false, host.ErrAbsent }

func TestEvaluate(t *testing.T) {
	two := int64(2)
	item := baseline.SysctlCheck{
		Key:    "kernel.kptr_restrict",
		Expect: check.Predicate{Gte: &two},
	}

	cases := map[string]struct {
		reader fakeReader
		want   check.Status
	}{
		"weaker fails":  {fakeReader{"kernel.kptr_restrict": "0"}, check.Fail},
		"equal passes":  {fakeReader{"kernel.kptr_restrict": "2"}, check.Pass},
		"absent skips":  {fakeReader{}, check.Skip},
		"unknown skips": {fakeReader{"kernel.kptr_restrict": "yes"}, check.Skip},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			findings := Evaluate([]baseline.SysctlCheck{item}, tc.reader)
			if len(findings) != 1 || findings[0].Status != tc.want {
				t.Fatalf("findings = %+v, want one %q", findings, tc.want)
			}
		})
	}
}
