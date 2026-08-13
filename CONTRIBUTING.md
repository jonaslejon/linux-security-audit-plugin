# Contributing

## The one rule

`FAIL` means "checked, and it is wrong". It never means "could not determine".

Every check whose prerequisite is missing must emit `NA` with the reason. `NA` is not a pass and
not a failure; it is the honest statement that the run could not establish the answer. The inverse
matters just as much: never emit `PASS` from a read that returned nothing. "No world-writable
files found" is a lie if the directory was unreadable.

This is the whole point of the project. A scanner that invents findings costs an operator more
than one that misses them, because after the second bogus finding nobody reads the third.

## Adding a check

1. Put it in the section it belongs to, and tag its method correctly:
   - `static` reads files on disk. It works against a mounted image.
   - `runtime` reads live kernel or process state (`/proc`, `ps`, `ss`, `lsmod`, `systemctl`) or
     queries an installed binary. Offline this is meaningless, and `chk()` will force it to `NA`.
   - `active` touches a service or the network. `--passive` suppresses it.

   Getting this wrong is not cosmetic. A runtime check mistagged `static` will report the auditing
   machine's state as the image's. If you switch method mid-section with `runtime_on`, reset it
   with `method_reset` afterwards, or every later check in that section inherits it.

2. Read files through `rf`, never as bare absolute paths:

   ```sh
   cat "$(rf /etc/login.defs)"          # correct
   cat /etc/login.defs                  # reads the auditing host under --root
   "$LSA_ROOT"/etc/cron.d/*             # correct for globs, which must expand after prefixing
   ```

   `/proc`, `/sys`, `/dev` and `/run` are deliberately excluded: they belong to the running host,
   so they must be `NA` guarded offline rather than resolved into the image.

3. Do not truncate evidence with `head -N`. Use `cap N`, which prints the same lines but says
   how many were dropped. A list silently cut from 213 entries to 80 reads as a complete list.

4. Never print a secret's value. Use `emit_secret` or `redact_env`.

## Tests

```sh
bash tests/offline-regression.sh     # the --root contract, argument handling, redaction
bash tests/metadata-consistency.sh   # counts, versions and changelog agree
shellcheck -S warning plugins/linux-security-audit/skills/linux-security-audit/scripts/lsa-trace.sh tests/*.sh
```

CI runs these plus a live collection on a real Linux runner, which is the coverage fixtures cannot
give. If you add a check that could plausibly read the wrong machine or invent a verdict, add a
case to `tests/offline-regression.sh`. The empty-tree assertion in there is the strongest one: point
`--root` at an empty directory, and anything the collector still claims to have observed, it did
not read from the tree.

## Documentation

`references/` is the authority for interpreting output, so a new check usually needs a line there
explaining what the control defends against and its distro or version caveats. Keep the check
count in the READMEs and `marketplace.json` in step; `tests/metadata-consistency.sh` enforces it.

## Style

Plain POSIX-ish bash, no dependencies beyond what is being audited. The collector runs on hosts
that deliberately have no compiler, no tcpdump and sometimes only busybox, and it should degrade
to `NA` rather than fail when a tool is missing. Avoid em dashes in output and documentation: they
render badly on 7-bit serial consoles, which is exactly where this gets read during an incident.
