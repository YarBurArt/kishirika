package check

import (
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
)

type Status string

const (
	Pass Status = "pass"
	Fail Status = "fail"
	Skip Status = "skip"
)

type Severity string

const (
	Info     Severity = "info"
	Low      Severity = "low"
	Medium   Severity = "medium"
	High     Severity = "high"
	Critical Severity = "critical"
)

var severityRank = map[Severity]int{Info: 0, Low: 1, Medium: 2, High: 3, Critical: 4}

func (s Severity) Rank() int { return severityRank[s] }

// Predicate is "not weaker than the baseline": >= accepts 2 where the profile
// asked 1, and `in` handles 2|3|4, which has no order.
type Predicate struct {
	Eq  *int64  `json:"eq,omitempty"`
	In  []int64 `json:"in,omitempty"`
	Gte *int64  `json:"gte,omitempty"`
}

func (p Predicate) Met(value int64) bool {
	switch {
	case p.Eq != nil:
		return value == *p.Eq
	case len(p.In) > 0:
		for _, want := range p.In {
			if value == want {
				return true
			}
		}
		return false
	case p.Gte != nil:
		return value >= *p.Gte
	}
	return false
}

func (p Predicate) String() string {
	switch {
	case p.Eq != nil:
		return strconv.FormatInt(*p.Eq, 10)
	case len(p.In) > 0:
		parts := make([]string, len(p.In))
		for i, want := range p.In {
			parts[i] = strconv.FormatInt(want, 10)
		}
		return "one of " + strings.Join(parts, ", ")
	case p.Gte != nil:
		return ">= " + strconv.FormatInt(*p.Gte, 10)
	}
	return "?"
}

type Finding struct {
	Family    string   `json:"family"`
	Key       string   `json:"key"`
	Expect    string   `json:"expect"`
	Actual    string   `json:"actual"`
	Status    Status   `json:"status"`
	Severity  Severity `json:"severity"`
	Reason    string   `json:"reason,omitempty"`
	Rationale string   `json:"rationale,omitempty"`
}

type Host struct {
	Hostname string `json:"hostname"`
	Kernel   string `json:"kernel"`
	OS       string `json:"os"`
}

type Family struct {
	Name     string    `json:"name"`
	Ran      bool      `json:"ran"`
	Reason   string    `json:"reason,omitempty"`
	Findings []Finding `json:"-"`
}

type Result struct {
	Host     Host
	Families []Family
}

type Counts struct {
	Pass int `json:"pass"`
	Fail int `json:"fail"`
	Skip int `json:"skip"`
}

func (c *Counts) Add(f Finding) {
	switch f.Status {
	case Pass:
		c.Pass++
	case Fail:
		c.Fail++
	case Skip:
		c.Skip++
	}
}

func (r Result) Counts() Counts {
	var c Counts
	for _, fam := range r.Families {
		for _, f := range fam.Findings {
			c.Add(f)
		}
	}
	return c
}

func (r Result) Findings() []Finding {
	total := 0
	for _, fam := range r.Families {
		total += len(fam.Findings)
	}

	out := make([]Finding, 0, total)
	for _, fam := range r.Families {
		out = append(out, fam.Findings...)
	}
	SortFindings(out)
	return out
}

func (r Result) AnyRan() bool {
	for _, fam := range r.Families {
		if fam.Ran {
			return true
		}
	}
	return false
}

// Writes results by index so the output order stays fixed. Eight workers is
// where the syscall-bound reads stop scaling (benchmarked 4, 12, 16 and 32).
func MapAll[T any](items []T, fn func(T) Finding) []Finding {
	out := make([]Finding, len(items))
	workers := min(runtime.GOMAXPROCS(0), 8, len(items))
	if workers < 2 {
		for i, item := range items {
			out[i] = fn(item)
		}
		return out
	}

	chunk := (len(items) + workers - 1) / workers
	var wg sync.WaitGroup
	for start := 0; start < len(items); start += chunk {
		end := min(start+chunk, len(items))
		wg.Add(1)
		go func(start, end int) {
			defer wg.Done()
			for i := start; i < end; i++ {
				out[i] = fn(items[i])
			}
		}(start, end)
	}
	wg.Wait()
	return out
}

// Keeps repeated runs byte-identical. slices.SortFunc: sort.Slice reflects a
// swapper and allocates it on every call.
func SortFindings(findings []Finding) {
	slices.SortFunc(findings, func(a, b Finding) int {
		if a.Family != b.Family {
			return strings.Compare(a.Family, b.Family)
		}
		if left, right := a.Severity.Rank(), b.Severity.Rank(); left != right {
			return right - left
		}
		return strings.Compare(a.Key, b.Key)
	})
}
