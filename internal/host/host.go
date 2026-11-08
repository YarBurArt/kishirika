package host

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

var (
	ErrAbsent = errors.New("absent")
	ErrDenied = errors.New("permission denied")
)

type Reader interface {
	Sysctl(key string) (string, error)
	Boolean(name string) (bool, error)
}

type Linux struct {
	SysctlRoot  string
	BooleanRoot string
}

func NewLinux() *Linux {
	return &Linux{
		SysctlRoot:  "/proc/sys",
		BooleanRoot: "/sys/fs/selinux/booleans",
	}
}

func (l *Linux) Sysctl(key string) (string, error) {
	return l.readFile(filepath.Join(l.SysctlRoot, strings.ReplaceAll(key, ".", "/")))
}

// Boolean reads the first field: selinuxfs writes "current pending".
func (l *Linux) Boolean(name string) (bool, error) {
	raw, err := l.readFile(filepath.Join(l.BooleanRoot, name))
	if err != nil {
		return false, err
	}
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return false, ErrAbsent
	}
	return fields[0] == "1", nil
}

func (l *Linux) SysctlAvailable() bool {
	return isDir(l.SysctlRoot)
}

func (l *Linux) SelinuxAvailable() bool {
	return isDir(l.BooleanRoot)
}

func (l *Linux) Hostname() string {
	name, err := os.Hostname()
	if err != nil || name == "" {
		return "unknown"
	}
	return name
}

func (l *Linux) Kernel() string {
	release, err := l.readFile(filepath.Join(l.SysctlRoot, "kernel", "osrelease"))
	if err != nil || release == "" {
		return "unknown"
	}
	return release
}

func (l *Linux) OS() string {
	raw, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "unknown"
	}
	for _, line := range strings.Split(string(raw), "\n") {
		name, value, ok := strings.Cut(line, "=")
		if ok && name == "PRETTY_NAME" {
			return strings.Trim(strings.TrimSpace(value), `"`)
		}
	}
	return "unknown"
}

func (l *Linux) readFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "", ErrAbsent
	case errors.Is(err, os.ErrPermission):
		return "", ErrDenied
	case err != nil:
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
