package main

import (
	"io"
	"testing"

	"github.com/YarBurArt/kishirika/internal/host"
)

// Whole CLI path on a live host: the profile splits the run across host info,
// the checks and the report.
func BenchmarkRun(b *testing.B) {
	cases := []struct {
		name string
		args []string
	}{
		{"text", []string{"--verbose"}},
		{"json", []string{"--json"}},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			linux := host.NewLinux()
			b.ReportAllocs()

			for b.Loop() {
				if code := runWith(tc.args, io.Discard, io.Discard, linux); code > exitFindings {
					b.Fatalf("exit %d", code)
				}
			}
		})
	}
}
