# platform-claim-audit

Version 0.1.0. A stdlib-only, offline static CLI for Python 3.9+.
Works on Windows, macOS and Linux.

It compares platform promises in root README.md and docs/**/*.md with
production Python source. It never imports or executes target code, uses the
network, or opens .env files. Test files and tests/, fixtures/, docs/ trees
are excluded from code evidence. Malformed Python files are skipped.

```sh
pip install .
platform-claim-audit path/to/project --json
python3 -m platform_claim_audit path/to/project --verbose
```

Exit codes: 0 PASS, 2 FAIL, 1 usage/input error. --version prints 0.1.0.
--fail-on HIGH|MEDIUM defaults to MEDIUM; the sole rule is HIGH.
--ignore documented-platform-unsupported suppresses that rule.
--verbose adds `OK platform <platform>` lines to human output.
JSON includes status, findings, verified_claims, and summary counts.
Findings contain rule, severity, docs_file, docs_line, claim, code_file,
code_line, and api; ordering is deterministic. Ignored findings do not
make contradicted claims verified.

Claims include cross-platform/cross platform, works on/runs on/supports/
support for/supported on followed by platform names, platform support,
platform-only, requires platform, and platform required. Aliases: win32/win,
mac/osx/darwin. Negative claims (not supported on, no platform support,
platform not supported, does not support) remove platforms globally;
negative lines never add claims. Fenced examples are excluded; inline code
counts. First positive claim provenance is retained across README then sorted
docs paths.

The sole rule, documented-platform-unsupported (HIGH), reports one finding
per claimed platform and incompatible API, with the first offending source
location. Silent docs pass. Claims with no production Python sources produce
one finding per platform, using `<no-source>` and code line 0.

## API table

| Available on | Modules | Attributes |
| --- | --- | --- |
| Windows | winreg, msvcrt, _winapi, winsound, nt | os.startfile, ctypes.windll, ctypes.WinDLL, ctypes.oledll |
| POSIX (macOS/Linux) | fcntl, pwd, grp, termios, resource, syslog | os.fork, os.setsid, os.getuid, os.geteuid, os.getgid, os.uname |

Imports, from-imports, aliases, calls, and bare attribute references count.
try blocks catching ImportError (including tuples or bare except) suppress
evidence. Resolved sys.platform equality and startswith checks recognize
win/win32/cygwin, darwin, linux; os.name checks recognize nt/posix.
Resolved branches restrict evidence to their platforms; wrong guards still
fail. Negated, compound, or unresolved tests are conservatively unguarded.

## Limits and neighbours

The table is deliberately small; unknown APIs and platforms such as FreeBSD
and Android are ignored. No honest macOS-only stdlib row is included, though
macOS promises can fail on Windows-only APIs. This is static evidence, not
proof of runtime compatibility. Aliases are tracked per file, without full
control-flow or variable rebinding analysis. Source text is never executed.

CI matrices execute real code across operating systems. readme-claim-audit
checks install names, flags, links and versions; dep-claim-audit checks
dependencies and Python versions; api-claim-audit checks promised symbols
and signatures; privacy-claim-audit checks network/telemetry evidence.
Bandit and Ruff check code issues. This tool complements these tools by
checking documentation platform promises.

## Development

Run `PYTHONPATH=src python3 -m unittest discover -s tests -v`.
Build with `python3 -m build`. Both wheel and sdist contain package metadata;
the sdist also includes the tests and good/bad fixtures. No runtime dependencies.
