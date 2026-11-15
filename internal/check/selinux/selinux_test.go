package selinux

import (
	"testing"

	"github.com/YarBurArt/kishirika/internal/baseline"
	"github.com/YarBurArt/kishirika/internal/check"
	"github.com/YarBurArt/kishirika/internal/host"
)

type fakeReader map[string][2]bool

func (f fakeReader) Boolean(name string) (current, pending bool, err error) {
	pair, ok := f[name]
	if !ok {
		return false, false, host.ErrAbsent
	}
	return pair[0], pair[1], nil
}

func (f fakeReader) Sysctl(string) (string, error) { return "", host.ErrAbsent }

func TestEvaluate(t *testing.T) {
	item := baseline.SELinuxCheck{Key: "deny_ptrace", Expect: "on"}

	cases := map[string]struct {
		reader fakeReader
		want   check.Status
	}{
		"off fails":      {fakeReader{"deny_ptrace": {false, false}}, check.Fail},
		"on passes":      {fakeReader{"deny_ptrace": {true, true}}, check.Pass},
		"absent skips":   {fakeReader{}, check.Skip},
		"flipped fails":  {fakeReader{"deny_ptrace": {true, false}}, check.Fail},
		"reverted fails": {fakeReader{"deny_ptrace": {false, true}}, check.Fail},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			findings := Evaluate([]baseline.SELinuxCheck{item}, tc.reader, nil)
			if len(findings) != 1 || findings[0].Status != tc.want {
				t.Fatalf("findings = %+v, want one %q", findings, tc.want)
			}
		})
	}
}

func TestState(t *testing.T) {
	cases := map[string]struct {
		state *host.SELinux
		want  [2]check.Status
	}{
		"in sync":      {&host.SELinux{Mode: "enforcing", Config: "enforcing", Policy: "targeted"}, [2]check.Status{check.Pass, check.Pass}},
		"booted loose": {&host.SELinux{Mode: "permissive", Config: "enforcing", Policy: "targeted"}, [2]check.Status{check.Fail, check.Pass}},
		"no config":    {&host.SELinux{Mode: "disabled"}, [2]check.Status{check.Skip, check.Fail}},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			findings := stateFindings(tc.state)
			if len(findings) != len(tc.want) {
				t.Fatalf("findings = %+v, want %d", findings, len(tc.want))
			}
			for i, want := range tc.want {
				if findings[i].Status != want {
					t.Errorf("%s = %q, want %q", findings[i].Key, findings[i].Status, want)
				}
			}
		})
	}
}

func BenchmarkEvaluateLive(b *testing.B) {
	checks := baseline.SELinux()
	linux := host.NewLinux()
	b.ReportAllocs()

	for b.Loop() {
		Evaluate(checks, linux, nil)
	}
}
