# kishirika

Go rewrite of KernelVulnAuditP, which checks whether public kernel exploits actually work on a host. This build is only the hardening half: kernel parameters from procfs and SELinux booleans from selinuxfs, checked against a baseline embedded in the binary.

Everything is read-only and needs no root, config file or database.

## Requirements

- Go 1.26 or newer to build
- Linux with procfs, plus selinuxfs for the SELinux checks

## Installation

```bash
git clone https://github.com/YarBurArt/kishirika.git
cd kishirika
go build -trimpath -buildvcs=false -ldflags="-s -w" -o bin/kishirika ./cmd/kishirika
```

## Usage

| flag | what |
| --- | --- |
| `-c`, `--check-hardening` | both families, and the default |
| `-p`, `--sysctl` | kernel parameters only |
| `-e`, `--selinux` | SELinux booleans only |
| `-v`, `--verbose` | print passing checks |
| `--json` | JSON output |
| `-h`, `--help` | help |

```bash
./bin/kishirika
./bin/kishirika --selinux -v
./bin/kishirika --json
```

The checks are tested against a fake `host.Reader`; run `go test ./...`.

## TODO

- CVE lookup for the running kernel and PoC search
- PoC execution in a sandbox (qemu, virtme-ng)
- TUI and reports
- Filters by family and severity
- SELinux state checks (mode vs config, policy name) and boolean persistence
- Policy modules (`unconfined`, `permissivedomains`)

## Public data from

- https://github.com/CISOfy/lynis
- https://github.com/fedora-selinux/selinux-playbooks
