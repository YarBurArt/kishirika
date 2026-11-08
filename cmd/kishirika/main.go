package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/YarBurArt/kishirika/internal/baseline"
	"github.com/YarBurArt/kishirika/internal/check"
	"github.com/YarBurArt/kishirika/internal/check/selinux"
	"github.com/YarBurArt/kishirika/internal/check/sysctl"
	"github.com/YarBurArt/kishirika/internal/host"
	"github.com/YarBurArt/kishirika/internal/report"
)

const toolVersion = "0.1.0"

const (
	exitClean       = 0
	exitFindings    = 1
	exitUsage       = 2
	exitUnsupported = 3
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	return runWith(args, stdout, stderr, host.NewLinux())
}

func runWith(args []string, stdout, stderr io.Writer, linux *host.Linux) int {
	for _, arg := range args {
		if arg == "-h" || arg == "--help" || arg == "help" {
			usage(stdout)
			return exitClean
		}
	}

	fs := flag.NewFlagSet("kishirika", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { usage(stderr) }

	var both, params, selinuxOnly, verbose bool
	fs.BoolVar(&both, "check-hardening", false, "")
	fs.BoolVar(&both, "c", false, "")
	fs.BoolVar(&params, "sysctl", false, "")
	fs.BoolVar(&params, "p", false, "")
	fs.BoolVar(&selinuxOnly, "selinux", false, "")
	fs.BoolVar(&selinuxOnly, "e", false, "")
	fs.BoolVar(&verbose, "verbose", false, "")
	fs.BoolVar(&verbose, "v", false, "")
	asJSON := fs.Bool("json", false, "")

	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "kishirika: unexpected argument %q\n\n", fs.Arg(0))
		usage(stderr)
		return exitUsage
	}

	wantSysctl, wantSelinux := params, selinuxOnly
	if both || (!wantSysctl && !wantSelinux) {
		wantSysctl, wantSelinux = true, true
	}

	sysctlBase, err := baseline.LoadSysctl()
	if err != nil {
		fmt.Fprintf(stderr, "kishirika: %v\n", err)
		return exitUsage
	}
	selinuxBase, err := baseline.LoadSELinux()
	if err != nil {
		fmt.Fprintf(stderr, "kishirika: %v\n", err)
		return exitUsage
	}

	res := check.Result{
		Host: check.Host{
			Hostname: linux.Hostname(),
			Kernel:   linux.Kernel(),
			OS:       linux.OS(),
		},
	}

	// the two families share nothing but the reader, so they run side by side
	jobs := make([]func() check.Family, 0, 2)
	if wantSysctl {
		jobs = append(jobs, func() check.Family {
			return family(linux.SysctlAvailable(), linux.SysctlRoot, "procfs", sysctl.Family,
				func() []check.Finding { return sysctl.Evaluate(sysctlBase, linux) })
		})
	}
	if wantSelinux {
		jobs = append(jobs, func() check.Family {
			return family(linux.SelinuxAvailable(), linux.BooleanRoot, "selinuxfs", selinux.Family,
				func() []check.Finding { return selinux.Evaluate(selinuxBase, linux) })
		})
	}

	res.Families = make([]check.Family, len(jobs))
	var wg sync.WaitGroup
	for i, job := range jobs {
		wg.Add(1)
		go func(i int, job func() check.Family) {
			defer wg.Done()
			res.Families[i] = job()
		}(i, job)
	}
	wg.Wait()

	opt := report.Options{ToolVersion: toolVersion, Verbose: verbose, Now: time.Now()}
	if *asJSON {
		err = report.JSON(stdout, res, opt)
	} else {
		err = report.Text(stdout, res, opt)
	}
	if err != nil {
		fmt.Fprintf(stderr, "kishirika: %v\n", err)
		return exitUsage
	}

	switch counts := res.Counts(); {
	case !res.AnyRan():
		fmt.Fprintln(stderr, "kishirika: nothing could be checked on this host")
		return exitUnsupported
	case counts.Fail > 0:
		return exitFindings
	default:
		return exitClean
	}
}

func family(available bool, root, mount, name string, evaluate func() []check.Finding) check.Family {
	if !available {
		return check.Family{Name: name, Reason: mount + " not mounted at " + root}
	}
	return check.Family{Name: name, Ran: true, Findings: evaluate()}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `kishirika - checks the practical functionality of Linux kernel exploits

for now just checks Kernel parameters and SELinux

- Run both checks (default):
  kishirika

- Kernel parameters only:
  kishirika --sysctl

- SELinux booleans only:
  kishirika --selinux

- Print passing checks too:
  kishirika -v

- Machine-readable output:
  kishirika --json

Flags:
  -c, --check-hardening  kernel parameters and SELinux booleans (default)
  -p, --sysctl           kernel parameters only
  -e, --selinux          SELinux booleans only
  -v, --verbose          print passing checks
      --json             machine-readable output
  -h, --help             show this help
`)
}
