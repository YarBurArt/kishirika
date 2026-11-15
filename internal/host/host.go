package host

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	ErrAbsent = errors.New("absent")
	ErrDenied = errors.New("permission denied")
)

// a stalled CDN must not hang the run.
const changeLogTimeout = 10 * time.Second

type Reader interface {
	Sysctl(key string) (string, error)
	Boolean(name string) (bool, error)
}

type Linux struct {
	SysctlRoot    string
	BooleanRoot   string
	SELinuxRoot   string
	SELinuxConfig string
	OSRelease     string
	Cmdline       string
	ChangeLogBase string

	mu    sync.Mutex
	dated map[string]time.Time
}

func NewLinux() *Linux {
	return &Linux{
		SysctlRoot:    "/proc/sys",
		BooleanRoot:   "/sys/fs/selinux/booleans",
		SELinuxRoot:   "/sys/fs/selinux",
		SELinuxConfig: "/etc/selinux/config",
		OSRelease:     "/etc/os-release",
		Cmdline:       "/proc/cmdline",
		ChangeLogBase: "https://cdn.kernel.org/pub/linux/kernel",
	}
}

// Info is what the report prints about the host it ran on.
type Info struct {
	Hostname  string    `json:"hostname"`
	Distro    string    `json:"distro"`
	Kernel    string    `json:"kernel"`
	Version   string    `json:"version"`
	Arch      string    `json:"arch"`
	BuildDate time.Time `json:"build_date,omitzero"`
	Cmdline   string    `json:"cmdline"`
	SELinux   *SELinux  `json:"selinux,omitempty"`
}

type SELinux struct {
	Mode   string `json:"mode"`
	Policy string `json:"policy"`
}

func (s *SELinux) String() string {
	switch {
	case s == nil:
		return ""
	case s.Policy == "":
		return s.Mode
	}
	return s.Mode + " (" + s.Policy + ")"
}

// The sources are independent and syscall-bound, so they are read together.
func (l *Linux) Info() Info {
	var (
		info Info
		wg   sync.WaitGroup
	)

	wg.Add(3)
	go func() {
		defer wg.Done()
		info.Kernel, _ = l.readFile(filepath.Join(l.SysctlRoot, "kernel", "osrelease"))
		info.Version, _ = l.readFile(filepath.Join(l.SysctlRoot, "kernel", "version"))
		info.Cmdline, _ = l.readFile(l.Cmdline)
	}()
	go func() {
		defer wg.Done()
		info.Distro = l.distro()
	}()
	go func() {
		defer wg.Done()
		info.SELinux = l.selinux()
	}()

	info.Hostname = hostName()
	info.Arch = machine()
	wg.Wait()

	if info.BuildDate, _ = parseBuildDate(info.Version); info.BuildDate.IsZero() {
		info.BuildDate = l.changeLogDate(info.Kernel)
	}
	return info
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

// The booted mode decides whether the policy can block an exploit at all. The
// name only exists in the config, so it is what will load, not what is loaded.
func (l *Linux) selinux() *SELinux {
	out := &SELinux{}
	if raw, err := os.ReadFile(l.SELinuxConfig); err == nil {
		out.Policy = keyValue(string(raw), "SELINUXTYPE")
	}

	mode, err := l.readFile(filepath.Join(l.SELinuxRoot, "enforce"))
	switch {
	case err == nil && mode == "1":
		out.Mode = "enforcing"
	case err == nil && mode == "0":
		out.Mode = "permissive"
	case errors.Is(err, ErrAbsent):
		// no selinuxfs: the kernel was booted without SELinux, or /sys is absent
		out.Mode = "disabled"
	}

	if out.Mode == "" && out.Policy == "" {
		return nil
	}
	return out
}

func (l *Linux) distro() string {
	raw, err := os.ReadFile(l.OSRelease)
	if err != nil {
		return ""
	}
	release := string(raw)
	if pretty := keyValue(release, "PRETTY_NAME"); pretty != "" {
		return pretty
	}
	return keyValue(release, "NAME")
}

func keyValue(raw, key string) string {
	for len(raw) > 0 {
		line, rest, _ := strings.Cut(raw, "\n")
		raw = rest
		name, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && name == key {
			return strings.Trim(value, `"`)
		}
	}
	return ""
}

var months = map[string]time.Month{
	"Jan": time.January, "Feb": time.February, "Mar": time.March,
	"Apr": time.April, "May": time.May, "Jun": time.June,
	"Jul": time.July, "Aug": time.August, "Sep": time.September,
	"Oct": time.October, "Nov": time.November, "Dec": time.December,
}

// The version string is free-form, but only a month name can start a stamp, so
// tokens are dropped as they are read.
func parseBuildDate(version string) (time.Time, bool) {
	for i := 0; i < len(version); {
		start, end, after := nextToken(version, i)
		if start == end {
			return time.Time{}, false
		}
		if month, ok := months[version[start:end]]; ok {
			if at, ok := parseStamp(version, month, after); ok {
				return at, true
			}
		}
		i = after
	}
	return time.Time{}, false
}

// Hand-parsed: time.Parse allocates an error for every layout it rejects before
// the right one.
func parseStamp(version string, month time.Month, after int) (time.Time, bool) {
	dayFrom, dayTo, i := nextToken(version, after)
	clockFrom, clockTo, i := nextToken(version, i)
	zoneFrom, zoneTo, i := nextToken(version, i)

	day, ok := atoi(version[dayFrom:dayTo])
	if !ok || day < 1 || day > 31 {
		return time.Time{}, false
	}
	hour, minute, second, ok := clock(version[clockFrom:clockTo])
	if !ok {
		return time.Time{}, false
	}

	loc := time.UTC
	yearFrom, yearTo := zoneFrom, zoneTo
	if tok := version[zoneFrom:zoneTo]; !isYear(tok) {
		loc = zone(tok)
		if yearFrom, yearTo, _ = nextToken(version, i); !isYear(version[yearFrom:yearTo]) {
			return time.Time{}, false
		}
	}

	year, ok := atoi(version[yearFrom:yearTo])
	if !ok {
		return time.Time{}, false
	}

	at := time.Date(year, month, day, hour, minute, second, 0, loc)
	// time.Date rolls a bad day over into the next month instead of failing
	if at.Day() != day || at.Month() != month {
		return time.Time{}, false
	}
	return at, true
}

// Only a numeric offset carries a real zone; abbreviations like CET are read as
// UTC, which is what kernels are built in.
func zone(tok string) *time.Location {
	if len(tok) == 5 && (tok[0] == '+' || tok[0] == '-') {
		hours, okHours := atoi(tok[1:3])
		minutes, okMinutes := atoi(tok[3:5])
		if okHours && okMinutes {
			offset := (hours*60 + minutes) * 60
			if tok[0] == '-' {
				offset = -offset
			}
			return time.FixedZone(tok, offset)
		}
	}
	return time.UTC
}

func clock(s string) (hour, minute, second int, ok bool) {
	if len(s) != 8 || s[2] != ':' || s[5] != ':' {
		return 0, 0, 0, false
	}
	if hour, ok = atoi(s[0:2]); !ok || hour > 23 {
		return 0, 0, 0, false
	}
	if minute, ok = atoi(s[3:5]); !ok || minute > 59 {
		return 0, 0, 0, false
	}
	if second, ok = atoi(s[6:8]); !ok || second > 59 {
		return 0, 0, 0, false
	}
	return hour, minute, second, true
}

func atoi(s string) (int, bool) {
	if len(s) == 0 || len(s) > 4 {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i] - '0'
		if c > 9 {
			return 0, false
		}
		n = n*10 + int(c)
	}
	return n, true
}

func isYear(s string) bool {
	if len(s) != 4 {
		return false
	}
	_, ok := atoi(s)
	return ok
}

func nextToken(s string, i int) (start, end, next int) {
	for i < len(s) && s[i] == ' ' {
		i++
	}
	if i == len(s) {
		return len(s), len(s), len(s)
	}
	start = i
	for i < len(s) && s[i] != ' ' {
		i++
	}
	return start, i, i
}

// Distro rebuilds like "Debian 6.1.119-1 (2024-11-22)" carry no date, so the
// release changelog answers. Cached including failures: one run asks about one
// kernel, and a retry only costs time.
func (l *Linux) changeLogDate(release string) time.Time {
	version, major, ok := kernelVersion(release)
	if !ok {
		return time.Time{}
	}

	l.mu.Lock()
	at, seen := l.dated[version]
	l.mu.Unlock()
	if seen {
		return at
	}

	at = l.fetchChangeLogDate(version, major)

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.dated == nil {
		l.dated = make(map[string]time.Time, 1)
	}
	l.dated[version] = at
	return at
}

func (l *Linux) fetchChangeLogDate(version, major string) time.Time {
	if l.ChangeLogBase == "" {
		return time.Time{}
	}

	ctx, cancel := context.WithTimeout(context.Background(), changeLogTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		l.ChangeLogBase+"/v"+major+".x/ChangeLog-"+version, nil)
	if err != nil {
		return time.Time{}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return time.Time{}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return time.Time{}
	}
	// the date is in the first commit header; the body runs to megabytes
	head, err := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if err != nil {
		return time.Time{}
	}
	at, _ := parseChangeLogDate(string(head))
	return at
}

// The "Date:" line is when the release was committed, not built.
func parseChangeLogDate(head string) (time.Time, bool) {
	for lines := 0; lines < 10 && len(head) > 0; lines++ {
		line, rest, _ := strings.Cut(head, "\n")
		head = rest

		stamp, ok := strings.CutPrefix(strings.TrimSpace(line), "Date:")
		if !ok {
			continue
		}
		stamp = strings.TrimSpace(stamp)
		for _, layout := range [...]string{
			"Mon Jan _2 15:04:05 2006 -0700",
			"Mon Jan _2 15:04:05 2006",
		} {
			if at, err := time.Parse(layout, stamp); err == nil {
				return at, true
			}
		}
	}
	return time.Time{}, false
}

// kernelVersion reduces a release to what the changelog is named after:
// "6.8.5-300.fc45.x86_64" is "6.8.5" in "v6.x".
func kernelVersion(release string) (version, major string, ok bool) {
	base := release
	if i := strings.IndexAny(base, "-+"); i >= 0 {
		base = base[:i]
	}
	parts := strings.SplitN(base, ".", 4)
	if len(parts) < 2 || parts[0] == "" {
		return "", "", false
	}
	if len(parts) > 3 {
		parts = parts[:3]
	}
	return strings.Join(parts, "."), parts[0], true
}

// procfs and sysfs report size 0, so os.ReadFile grows and copies its buffer on
// every one of the ~140 reads per run.
var readBuffers = sync.Pool{
	New: func() any {
		buf := make([]byte, 0, 4096)
		return &buf
	},
}

// TODO: opening costs more than reading here. A raw fd read was 1.6x faster,
// but too ugly to keep.
func (l *Linux) readFile(path string) (string, error) {
	f, err := os.Open(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "", ErrAbsent
	case errors.Is(err, os.ErrPermission):
		return "", ErrDenied
	case err != nil:
		return "", err
	}
	defer f.Close()

	buffered := readBuffers.Get().(*[]byte)
	defer readBuffers.Put(buffered)

	buf := (*buffered)[:cap(*buffered)]
	n, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return "", err
	}

	// a full buffer means the file is at least as long as the buffer
	if n == len(buf) {
		rest, err := io.ReadAll(f)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(buf) + string(rest)), nil
	}
	return strings.TrimSpace(string(buf[:n])), nil
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func hostName() string {
	name, err := os.Hostname()
	if err != nil {
		return ""
	}
	return name
}

func machine() string {
	var uts syscall.Utsname
	if err := syscall.Uname(&uts); err != nil {
		return ""
	}
	return cString(uts.Machine[:])
}

// The utsname fields are [65]int8 on some Linux arches and [65]uint8 on the
// rest, hence the generic.
func cString[T ~int8 | ~uint8](field []T) string {
	out := make([]byte, 0, len(field))
	for _, c := range field {
		if c == 0 {
			break
		}
		out = append(out, byte(c))
	}
	return string(out)
}
