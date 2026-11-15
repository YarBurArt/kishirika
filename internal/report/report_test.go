package report

import (
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/YarBurArt/kishirika/internal/check"
	"github.com/YarBurArt/kishirika/internal/host"
)

func BenchmarkText(b *testing.B) {
	res, info, opt := benchInput()
	b.ReportAllocs()
	for b.Loop() {
		if err := Text(io.Discard, res, info, opt); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkJSON(b *testing.B) {
	res, info, opt := benchInput()
	b.ReportAllocs()
	for b.Loop() {
		if err := JSON(io.Discard, res, info, opt); err != nil {
			b.Fatal(err)
		}
	}
}

func benchInput() (check.Result, host.Info, Options) {
	families := []check.Family{
		{Name: "sysctl", Ran: true, Findings: benchFindings("sysctl", "kernel.kptr_restrict")},
		{Name: "selinux", Ran: true, Findings: benchFindings("selinux", "deny_ptrace")},
	}
	info := host.Info{
		Hostname:  "testhost",
		Distro:    "Example Linux 1.0",
		Kernel:    "6.1.0-example.x86_64",
		Version:   "#1 SMP PREEMPT_DYNAMIC Tue Jan  2 03:04:05 UTC 2024",
		Arch:      "x86_64",
		BuildDate: time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
		Cmdline:   "BOOT_IMAGE=/vmlinuz-6.1.0-example.x86_64 ro quiet",
		SELinux:   &host.SELinux{Mode: "enforcing", Config: "enforcing", Policy: "targeted"},
	}
	return check.Result{Families: families}, info, Options{ToolVersion: "0.1.0", Verbose: true}
}

func benchFindings(family, key string) []check.Finding {
	out := make([]check.Finding, 40)
	for i := range out {
		out[i] = check.Finding{
			Family:   family,
			Key:      fmt.Sprintf("%s.%d", key, i),
			Expect:   ">= 2",
			Actual:   "0",
			Status:   check.Fail,
			Severity: check.Medium,
			Reason:   "weaker than the baseline",
		}
	}
	return out
}
