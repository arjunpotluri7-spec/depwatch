# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |
| < 0.1 | No |

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's **private vulnerability reporting**:
open the repository's **Security** tab and choose **Report a vulnerability**. Do not open a
public issue for security problems.

Include the Depwatch version, Java version and OS, a minimal input that reproduces the problem
(synthetic data only, please), and what you expected to happen.

## What to expect

- Acknowledgement within 5 business days.
- An initial assessment within 10 business days.
- A fix or mitigation plan for confirmed issues, with credit in the release notes if you want
  it. Please allow a reasonable time for a fix before public disclosure.

## Scope

In scope: anything in this repository that could let a crafted POM, lockfile, SBOM, advisory
record or configuration file cause code execution, network access, reading files other than the
named inputs, writes outside the requested output path, denial of service out of proportion to
the input size, or a misleading result (for example a version wrongly reported as unaffected, a
wrong "smallest safe upgrade", or a location that points at the wrong line).

Out of scope: gaps in the advisory data you supply (Depwatch can only report what the database
contains), and issues in third-party dependencies that are already public.

## Security design

- **Read-only and offline.** Depwatch reads only the files named on the command line and the
  `--db` folder. It makes no network connections and runs no subprocesses. Input files are never
  modified or executed.
- **XXE defense.** POMs are parsed with a hardened SAX parser: DOCTYPE declarations are rejected,
  external entities, external DTDs and XInclude are disabled, secure processing is on, external
  DTD and schema access is empty, and the entity resolver refuses all lookups. A file containing
  a DOCTYPE is rejected with exit code 2. Test fixtures in `src/test/resources/xxe/` cover
  external entities, entity expansion, external DTDs and XInclude.
- **Safe YAML.** The configuration and `--licenses` files are loaded with SnakeYAML's
  `SafeConstructor` (no Java object construction), duplicate keys rejected, alias expansion
  limited.
- **Strict JSON.** Duplicate keys and trailing content are rejected; nesting depth and string
  sizes are limited.
- **Resource limits.** Every file read is capped (`--max-file-size`, default 32 MiB). Property
  interpolation is bounded in depth, length and expansion count; XML element count and depth are
  bounded; the database walk is bounded in depth and file count.
- **Symlinks.** Symbolic links inside the database folder are not followed unless
  `--follow-symlinks` is given. Reports are never written through a symbolic link.
- **Output safety.** Reports are written with mode 0600 where supported and never overwrite an
  existing file without `--force`. Control characters, including terminal escape sequences, are
  removed from untrusted text before it is printed, and Markdown output is escaped.
- **Fail closed.** A rejected input file makes `scan` exit with 2 even if other inputs were
  clean, and advisories without a severity count as high for `--fail-on`.
