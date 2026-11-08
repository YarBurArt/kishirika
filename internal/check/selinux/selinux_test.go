package selinux

import (
	"testing"

	"github.com/YarBurArt/kishirika/internal/baseline"
	"github.com/YarBurArt/kishirika/internal/check"
	"github.com/YarBurArt/kishirika/internal/host"
)

type fakeReader map[string]bool

func (f fakeReader) Boolean(name string) (bool, error) {
	value, ok := f[name]
	if !ok {
		return false, host.ErrAbsent
	}
	return value, nil
}

func (f fakeReader) Sysctl(string) (string, error) { return "", host.ErrAbsent }

func TestEvaluate(t *testing.T) {
	item := baseline.SELinuxCheck{Key: "deny_ptrace", Expect: "on"}

	cases := map[string]struct {
		reader fakeReader
		want   check.Status
	}{
		"off fails":    {fakeReader{"deny_ptrace": false}, check.Fail},
		"on passes":    {fakeReader{"deny_ptrace": true}, check.Pass},
		"absent skips": {fakeReader{}, check.Skip},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			findings := Evaluate([]baseline.SELinuxCheck{item}, tc.reader)
			if len(findings) != 1 || findings[0].Status != tc.want {
				t.Fatalf("findings = %+v, want one %q", findings, tc.want)
			}
		})
	}
}
