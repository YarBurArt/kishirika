package check

import (
	"errors"
	"runtime"
	"sort"
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

func (s Severity) Valid() bool {
	_, ok := severityRank[s]
	return ok
}

func (s Severity) Rank() int { return severityRank[s] }

// Predicate is "not weaker than the baseline": >= accepts 2 where the profile
// asked 1, and `in` handles 2|3|4, which has no order.
type Predicate struct {
	Eq  *int64  `json:"eq,omitempty"`
	In  []int64 `json:"in,omitempty"`
	Gte *int64  `json:"gte,omitempty"`
}

func (p Predicate) Validate() error {
	set := 0
	if p.Eq != nil {
		set++
	}
	if len(p.In) > 0 {
		set++
	}
	if p.Gte != nil {
		set++
	}
	if set != 1 {
		return errors.New("expect must set exactly one of eq, in, gte")
	}
	return nil
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
	out := make([]Finding, 0, 128)
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

// MapAll reads in parallel and writes results by index, so the output order
// stays fixed.
func MapAll[T any](items []T, fn func(T) Finding) []Finding {
	out := make([]Finding, len(items))
	workers := min(runtime.GOMAXPROCS(0), 4, len(items))
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

// SortFindings keeps repeated runs byte-identical: family, then severity, then key.
func SortFindings(findings []Finding) {
	sort.Slice(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Family != b.Family {
			return a.Family < b.Family
		}
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		return a.Key < b.Key
	})
}
