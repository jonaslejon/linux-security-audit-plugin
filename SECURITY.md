# Security policy

## Reporting

Report anything security-relevant through GitHub's private vulnerability reporting on this
repository (Security tab, "Report a vulnerability"). Please do not open a public issue first.

## What counts as a vulnerability here

This tool runs as root, on production hosts, and reads files that hold credentials. That gives it
a threat model most audit scripts do not think about, and these are the things worth reporting
even though none of them is a memory-safety bug:

- **A secret value printed into the report.** The collector reads credential-bearing files to
  classify them and must only ever emit the file, the line, the variable name and the value's
  length. A path that prints the value itself is the highest-severity bug in this project. One
  such bug shipped: redaction that only masked after the last `=` on a line, so a unit file
  carrying two variables leaked the first. There is now a regression test for it.
- **A write to the audited system.** The collector is read-only by default. `--apt-update` is the
  single exception and is opt-in. Anything else that writes, creates or modifies state on the
  target is a bug.
- **A manufactured finding.** A `FAIL` that came from a failed read rather than a real
  observation, or a `PASS` asserted about something the collector never managed to read. Both
  cause real harm: the first burns an operator's time and credibility, the second certifies a
  control that is not there. `NA` is the correct answer whenever a prerequisite is missing.
- **Reading outside the target.** Under `--root` the collector must describe the mounted tree and
  nothing else. It previously described the auditing machine, which meant an image audit could
  report the auditor's own SSH host keys as baked into the customer's template.
- **Command injection through audited content.** Filenames, config values and package names come
  from an untrusted host. Anything that lets those reach `eval` or an unquoted expansion matters.

## What is not a vulnerability

- Findings you disagree with, or checks that are too strict for your environment. Open an issue.
- The active checks opening loopback connections to local services. That is documented behaviour
  and `--passive` disables it.
- The tool requiring root. Most of what it inspects is unreadable otherwise, and it reports `NA`
  rather than guessing when run unprivileged.

## Scope of the redaction guarantee

The collector aims never to print a secret's value. It does print file paths, line numbers,
variable names, value lengths and the first few characters of provider-token prefixes (enough to
identify which vendor's key it is). Treat a collected report as sensitive regardless: it is a
detailed map of where the credentials on a host live.
