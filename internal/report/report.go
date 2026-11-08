package report

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/YarBurArt/kishirika/internal/check"
)

// SchemaVersion is the JSON contract; bump it on any breaking change.
const SchemaVersion = 1

type Options struct {
	ToolVersion string
	Verbose     bool
	Now         time.Time
}

type jsonResult struct {
	SchemaVersion int             `json:"schema_version"`
	ToolVersion   string          `json:"tool_version"`
	GeneratedAt   time.Time       `json:"generated_at"`
	Host          check.Host      `json:"host"`
	Summary       check.Counts    `json:"summary"`
	Families      []check.Family  `json:"families"`
	Checks        []check.Finding `json:"checks"`
}

func Text(w io.Writer, res check.Result, opt Options) error {
	printed := false
	for _, fam := range res.Families {
		visible := shown(fam.Findings, opt.Verbose)
		if !fam.Ran || len(visible) == 0 {
			continue
		}
		if printed {
			fmt.Fprintln(w)
		}
		fmt.Fprintln(w, fam.Name)
		printed = true

		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		for _, f := range visible {
			if f.Status == check.Skip {
				target := f.Key
				if f.Actual != "" {
					target += " = " + f.Actual
				}
				fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n",
					upper(f.Status), f.Severity, target, f.Reason)
				continue
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s = %s\twant %s\n",
				upper(f.Status), f.Severity, f.Key, f.Actual, f.Expect)
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}

	if printed {
		fmt.Fprintln(w)
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, fam := range res.Families {
		fmt.Fprintf(tw, "%s:\t%s\n", fam.Name, summary(fam))
	}
	return tw.Flush()
}

func JSON(w io.Writer, res check.Result, opt Options) error {
	out := jsonResult{
		SchemaVersion: SchemaVersion,
		ToolVersion:   opt.ToolVersion,
		GeneratedAt:   opt.Now.UTC(),
		Host:          res.Host,
		Summary:       res.Counts(),
		Families:      res.Families,
		Checks:        res.Findings(),
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func shown(findings []check.Finding, verbose bool) []check.Finding {
	out := make([]check.Finding, 0, len(findings))
	for _, f := range findings {
		if verbose || f.Status == check.Fail {
			out = append(out, f)
		}
	}
	check.SortFindings(out)
	return out
}

func summary(fam check.Family) string {
	if !fam.Ran {
		return "not checked (" + fam.Reason + ")"
	}
	var counts check.Counts
	for _, f := range fam.Findings {
		counts.Add(f)
	}
	return fmt.Sprintf("%d pass, %d fail, %d skip",
		counts.Pass, counts.Fail, counts.Skip)
}

func upper(s check.Status) string {
	switch s {
	case check.Pass:
		return "PASS"
	case check.Fail:
		return "FAIL"
	case check.Skip:
		return "SKIP"
	}
	return string(s)
}
