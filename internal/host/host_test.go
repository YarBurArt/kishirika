package host

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

const (
	testRelease = "6.1.0-example.x86_64"
	testVersion = "#1 SMP PREEMPT_DYNAMIC Tue Jan  2 03:04:05 UTC 2024"
	testCmdline = "BOOT_IMAGE=/vmlinuz-6.1.0-example.x86_64 ro quiet"
)

func TestParseBuildDate(t *testing.T) {
	cases := map[string]struct {
		version string
		want    string
	}{
		"named zone":     {testVersion, "2024-01-02T03:04:05Z"},
		"no zone":        {"#1 SMP Fri Jan 2 03:04:05 2024", "2024-01-02T03:04:05Z"},
		"numeric offset": {"#1 SMP Fri Jan  2 03:04:05 -0500 2024", "2024-01-02T03:04:05-05:00"},
		"date only":      {"#1 SMP PREEMPT_DYNAMIC Debian 6.1.0-1 (2024-01-15)", ""},
		"empty":          {"", ""},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, ok := parseBuildDate(tc.version)
			if tc.want == "" {
				if ok {
					t.Fatalf("parseBuildDate(%q) = %v, want no date", tc.version, got)
				}
				return
			}

			want, err := time.Parse(time.RFC3339, tc.want)
			if err != nil {
				t.Fatal(err)
			}
			if !ok || !got.Equal(want) {
				t.Fatalf("parseBuildDate(%q) = %v, %v, want %v", tc.version, got, ok, want)
			}
		})
	}
}

// Most kernels stamp the date into the version string; distro rebuilds that
// strip it out fall back to the release changelog.
func TestInfo(t *testing.T) {
	t.Run("version string", func(t *testing.T) {
		info := fakeHost(t, testRelease, testVersion).Info()
		info.Hostname, info.Arch = "", "" // come from the machine running the test

		want := Info{
			Kernel:    testRelease,
			Version:   testVersion,
			Distro:    "Example Linux 1.0",
			Cmdline:   testCmdline,
			BuildDate: time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
			SELinux:   &SELinux{Mode: "enforcing", Config: "enforcing", Policy: "targeted"},
		}
		if !reflect.DeepEqual(info, want) {
			t.Fatalf("Info() = %+v, want %+v", info, want)
		}
	})

	t.Run("changelog fallback", func(t *testing.T) {
		hits := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits++
			if r.URL.Path != "/v6.x/ChangeLog-6.1.0" {
				http.NotFound(w, r)
				return
			}
			fmt.Fprint(w, changeLogHead)
		}))
		defer srv.Close()

		l := &Linux{
			SysctlRoot:    filepath.Join(t.TempDir(), "proc", "sys"),
			ChangeLogBase: srv.URL,
		}
		writeFile(t, filepath.Join(l.SysctlRoot, "kernel", "osrelease"), "6.1.0-1-amd64\n")
		writeFile(t, filepath.Join(l.SysctlRoot, "kernel", "version"), "#1 SMP PREEMPT_DYNAMIC Debian 6.1.0-1 (2024-01-15)\n")

		want := time.Date(2024, 1, 2, 3, 4, 5, 0, time.FixedZone("-0500", -5*60*60))
		for range 2 { // the second call has to come from the cache
			if got := l.Info().BuildDate; !got.Equal(want) {
				t.Fatalf("BuildDate = %s, want %s", got, want)
			}
		}
		if hits != 1 {
			t.Errorf("changelog fetched %d times, want 1", hits)
		}
	})
}

func BenchmarkParseBuildDate(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		if _, ok := parseBuildDate(testVersion); !ok {
			b.Fatal("no date")
		}
	}
}

func BenchmarkInfo(b *testing.B) {
	l := fakeHost(b, testRelease, testVersion)
	b.ReportAllocs()

	for b.Loop() {
		if l.Info().Kernel == "" {
			b.Fatal("no kernel")
		}
	}
}

const changeLogHead = `commit 0123456789abcdef0123456789abcdef01234567
Author: Kernel Maintainer <maintainer@example.org>
Date:   Mon Jan  2 03:04:05 2024 -0500

    Linux 6.1.0

    Signed-off-by: Kernel Maintainer <maintainer@example.org>
`

func fakeHost(t testing.TB, release, version string) *Linux {
	t.Helper()

	root := t.TempDir()
	l := &Linux{
		SysctlRoot:    filepath.Join(root, "proc", "sys"),
		SELinuxRoot:   filepath.Join(root, "selinux"),
		SELinuxConfig: filepath.Join(root, "selinux", "config"),
		OSRelease:     filepath.Join(root, "os-release"),
		Cmdline:       filepath.Join(root, "cmdline"),
	}

	writeFile(t, filepath.Join(l.SysctlRoot, "kernel", "osrelease"), release+"\n")
	writeFile(t, filepath.Join(l.SysctlRoot, "kernel", "version"), version+"\n")
	writeFile(t, filepath.Join(l.SELinuxRoot, "enforce"), "1\n")
	writeFile(t, l.SELinuxConfig, "SELINUX=enforcing\nSELINUXTYPE=targeted\n")
	writeFile(t, l.OSRelease, "NAME=\"Example Linux\"\nPRETTY_NAME=\"Example Linux 1.0\"\n")
	writeFile(t, l.Cmdline, testCmdline+"\n")

	return l
}

func writeFile(t testing.TB, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
