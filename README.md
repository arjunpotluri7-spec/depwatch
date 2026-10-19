# Depwatch

An offline dependency auditor for Maven and Gradle projects. It checks every dependency against a local OSV advisory snapshot and a license policy, says exactly **why** each version is affected, and names the **smallest safe upgrade**.

![CI](../../actions/workflows/ci.yml/badge.svg)

## Why this exists

Most dependency scanners answer "is this version vulnerable?" with a yes and a link. During triage the next questions matter more: *which range matched? does the fix version have its own advisory? can I stay on my major version, or is this a breaking upgrade?* Getting those answers usually means reading several advisories and doing Maven version arithmetic by hand, and that arithmetic has traps: `2.0-rc1` is *inside* `[1.0,2.0)`, `1.0-a` sorts *after* `1.0`, and `2.9.10.8` comes before `2.10.0`.

Depwatch does that work offline. It reads the dependency files you already have (`pom.xml`, `gradle.lockfile`, a CycloneDX SBOM), compares them with an OSV advisory folder you provide, and explains each result in one sentence with the real numbers. It never contacts a network service, so it works in air-gapped builds and gives the same answer every time for the same inputs.

## Distinctive feature: a tested Maven version engine

The core of Depwatch is its own implementation of Maven version ordering and ranges (no `maven-artifact` dependency):

- **Ordering** matching Maven's `ComparableVersion`: tokens split at `.`, `-` and digit/letter transitions; trailing "null" tokens trimmed at each hyphen (`1.0 == 1.0.0 == 1-0`, `1.ga == 1`); qualifiers ordered `alpha < beta < milestone < rc = cr < snapshot < "" = final = ga = release < sp`, then unknown qualifiers alphabetically; `a1`/`b1`/`m1` as shorthands; `.qualifier = -qualifier < -number < .number`; arbitrarily large numbers.
- **Range parsing**: `[1.2,2.0)`, `(,1.5]`, `[1.0]`, soft requirements like `1.0`, and unions like `[1,2),[3,4)`, with Maven's validation rules (no overlaps, a single version must be `[v]`, lower bound not above upper).
- **OSV `ECOSYSTEM` ranges**: `introduced` (including `"0"`), `fixed`, `last_affected` and `limit`, evaluated with the algorithm from the OSV schema, plus explicit `versions` lists.
- **Explanations**: `2.14.1 is in [2.0-beta9, 2.15.0) from DEMO-2026-0001 (introduced 2.0-beta9, fixed 2.15.0)`.
- **Smallest safe upgrade**: the lowest version at or above the current one that *no* known advisory affects, inside the same major version when possible and otherwise in the next major (and it says so). If a fix version is itself affected by another advisory it is skipped with the reason. If nothing safe is recorded (only `last_affected`, or only a `versions` list), it says that instead of guessing.

How it was checked:

- A table of **136 ordering cases** (`src/test/resources/version-order-cases.csv`) taken from the Maven POM reference "Version Order Specification" and the `ComparableVersion` javadoc, each source cited in the file, plus edge cases. Every pair is tested in both directions and for `equals`/`hashCode` consistency, and the table is checked for transitivity.
- Range containment tests built from the POM reference "Dependency Version Requirement Specification" examples.
- During development the engine was also compared, outside this repository, with Maven's own `maven-artifact` 3.9.16: all 136 table rows, 240,000 random comparisons of generated version strings (ordering, equality and canonical form) and 352 range-containment checks agreed. That comparison was a one-off local check; `maven-artifact` is not a dependency of this project and is not used by its tests.
- Two places where the Maven documentation and Maven's implementation disagree are documented in the tests. The POM reference lists `1-ga-1 = 1-1`, but `ComparableVersion` orders `1-ga-1 < 1-1`. And Maven's ordering is not transitive for strings shaped like `1-0.alpha` (`1 < 1-sp < 1-0.alpha < 1`). In both cases Depwatch follows the implementation, because that is what decides which version Maven builds with.

## Features

- **Three inputs, auto-detected** by file name, then by content (override with `--input-type`):
  - `pom.xml`: `<dependencies>`, `<dependencyManagement>` (used to fill in missing versions, and audited itself), `<properties>` with nested `${...}` interpolation (bounded depth, cycle detection), the `project.*` and `project.parent.*` built-ins, and `<parent>` coordinates (recorded, never fetched).
  - Gradle `gradle.lockfile` (`group:artifact:version=configurations`).
  - CycloneDX JSON SBOM: `pkg:maven/...` purls, nested components, `licenses` with ids, names and expressions.
- **OSV advisory folder** (`--db DIR`): `id`, `aliases`, `summary`, `details`, `severity`, `database_specific.severity`, `affected[].package` (ecosystem `Maven`, name `group:artifact`), `ranges` (`ECOSYSTEM` events), `versions`, `references`, `withdrawn`. Malformed records are skipped with a warning naming the file, the record and the problem.
- **Severity** from `database_specific.severity` when present, otherwise computed from the CVSS v3.0/v3.1 base vector with the FIRST formula and qualitative scale. Advisories without a usable severity are `unknown`, which counts as `high` for `--fail-on` so missing data cannot hide a finding.
- **License policy** (YAML): allowed, review-required and denied SPDX ids, SPDX expressions with `AND` / `OR` / `WITH` / `+`, and per-package exceptions that must each give a reason. Licenses come from the SBOM, or from a `--licenses` mapping file for POMs and lockfiles.
- **Suppressions** for accepted advisories, each with a required reason. Suppressed findings stay visible in every report and in SARIF (`suppressions[]`), but do not affect the exit code.
- **Reports**: terminal table (default), stable JSON (`depwatch-report/1`), SARIF 2.1.0 with file and line locations, and Markdown.
- **`explain`** shows every advisory for a package, matched or not and why, and the smallest safe upgrade. **`version compare`** and **`version in-range`** expose the engine for learning and scripts. **`db stats`** summarizes a database folder.
- **Defensive by design**: read-only and offline, hardened XML parsing (XXE defense, see [Security design](#security-design)), SnakeYAML `SafeConstructor`, size limits on every file, no subprocesses, no symlink following in the database folder unless asked, control characters stripped from untrusted text before it reaches a terminal, reports written `0600` and never overwritten without `--force`.

## Architecture

```
 pom.xml ───────┐   input/                         advisory/
 gradle.lockfile├─► PomParser (SecureXml,  ──► Dependency[] ──┐    OsvLoader ──► AdvisoryDatabase
 *.cdx.json ────┘   PropertyResolver)                         │    (OSV JSON)    (index by group:artifact)
                    GradleLockfileParser                      │         │
                    CycloneDxParser (PackageUrl)              ▼         ▼
                                                    scan/Scanner ─► match/AdvisoryMatcher ──► Check (why)
 config.yaml ──► config/ConfigLoader ──► LicensePolicy,      │          match/UpgradeAdvisor ──► smallest safe upgrade
 --licenses  ──► LicenseMap              Suppressions ───────┤
                                                             ▼
                                         Finding[] ──► report/: table | json | sarif | markdown
                                                             │
                                   version/: MavenVersion, VersionRange (used by everything above)
```

The library (everything outside `cli/`) has no CLI or picocli dependency; a test enforces this, and another checks that no source file uses network or process APIs.

| Package | Role |
|---|---|
| `version` | `MavenVersion` (ordering, canonical form, major, pre-release), `VersionRange` (Maven range parsing and containment) |
| `advisory` | `OsvLoader` (validation, skipping malformed records), `OsvRange` (event semantics and explanatory intervals), `Cvss3` (base score), `AdvisoryDatabase` (index and stats) |
| `match` | `AdvisoryMatcher` (affected / not affected / withdrawn, with a reason), `UpgradeAdvisor` (smallest safe upgrade) |
| `input` | `SecureXml` (hardened SAX parser with line numbers), `PomParser`, `PropertyResolver`, `GradleLockfileParser`, `CycloneDxParser`, `PackageUrl`, `InputReader` (detection) |
| `license` | `SpdxExpression` (parser), `LicensePolicy` (evaluation and exceptions) |
| `config` | `ConfigLoader` (strict YAML validation), `SafeYaml`, `Suppression`, `LicenseMap` |
| `scan` | `Scanner` (pipeline), `Finding`, `ScanResult` |
| `report` | `TableReport`, `JsonReport`, `SarifReport`, `MarkdownReport` |
| `cli` | picocli commands, exit codes, structured logging to stderr, safe report writing |

### Security design

- **Read-only and offline.** Depwatch reads only the files named on the command line and the `--db` folder. It opens no network connections and starts no processes; nothing it reads is executed or loaded as code.
- **XXE defense.** POMs are parsed with a SAX parser that rejects any DOCTYPE (`disallow-doctype-decl`), so no entity, internal or external, can be declared. External general and parameter entities, external DTD loading and XInclude are disabled as well, JAXP secure processing is on, `ACCESS_EXTERNAL_DTD` and `ACCESS_EXTERNAL_SCHEMA` are empty, and the entity resolver refuses every lookup. Element count, depth and text size are bounded.
- **Safe YAML and JSON.** Configuration uses SnakeYAML's `SafeConstructor` with duplicate-key rejection and alias limits. JSON parsing rejects duplicate keys and trailing content and limits nesting and string sizes.
- **Bounded work.** Every file has a size cap; property interpolation is limited in depth, length and number of expansions; the database walk has a file-count and depth limit.
- **No symlink surprises.** Symbolic links in the database folder are skipped unless `--follow-symlinks`. Reports are never written through a symbolic link.
- **Safe output.** Control characters (including terminal escape sequences) from advisory text are stripped before printing; Markdown output escapes structure characters.

See [`SECURITY.md`](SECURITY.md) for reporting vulnerabilities in Depwatch itself.

## Build & install

Requires JDK 17 (the version tested and targeted). The Gradle wrapper (9.8.2, pinned with a SHA-256 checksum) downloads Gradle itself; every library version is pinned in `gradle/libs.versions.toml` and locked in `gradle.lockfile`.

```bash
git clone <this repository> depwatch && cd depwatch
./gradlew build          # Spotless check, compile with -Xlint:all -Werror, all tests
./gradlew installDist    # creates build/install/depwatch/bin/depwatch
build/install/depwatch/bin/depwatch --version
```

- **macOS / Linux**: as above. CI runs on `ubuntu-latest` and `macos-latest` with Temurin 17.
- **Windows**: use `gradlew.bat build installDist` and `build\install\depwatch\bin\depwatch.bat`. The code avoids platform-specific APIs, but Windows is not tested in CI, and report paths there use backslash separators.

Runtime dependencies: picocli 4.7.7, Jackson Databind 2.22.4, SnakeYAML 2.7.

## Quick start against `samples/`

Everything in `samples/` is synthetic: fictional `com.example` / `org.example` packages and `DEMO-2026-NNNN` advisories (see [`samples/README.md`](samples/README.md)).

```bash
bin=build/install/depwatch/bin/depwatch

# Audit a POM (properties, dependencyManagement, a parent that is not fetched)
$bin scan samples/maven-app/pom.xml --db samples/osv-db

# Everything at once, with the license policy and suppressions, including test dependencies
$bin scan samples/maven-app/pom.xml samples/gradle-app/gradle.lockfile samples/sbom/app.cdx.json \
  --db samples/osv-db --config config.example.yaml --include-dev

# Why is this version affected, and what is the smallest safe upgrade?
$bin explain com.example:logkit:2.14.1 --db samples/osv-db

# The version engine on its own
$bin version compare 2.0-rc1 2.0
$bin version in-range 2.0-rc1 '[1.0,2.0)'
$bin db stats --db samples/osv-db
```

### Using real advisory data

Depwatch never downloads anything. To scan real projects, download an OSV export for the Maven ecosystem yourself and point `--db` at the unzipped folder. At the time of writing the OSV project publishes per-ecosystem archives (for Maven, `https://osv-vulnerabilities.storage.googleapis.com/Maven/all.zip`); see the OSV documentation on data dumps for the current location. Verify the download the way your organization requires before using it. Depwatch has been tested with the synthetic sample database and generated records, **not** with a full real export (see [Limitations](#limitations)).

## Usage

```
depwatch scan INPUT... --db DIR [--config FILE] [--licenses FILE] [--input-type pom|gradle-lockfile|cyclonedx]
              [--format table|json|sarif|markdown] [-o|--output FILE] [--force]
              [--fail-on none|low|medium|high|critical] [--include-dev]
              [--max-file-size MIB] [--follow-symlinks] [--log-level LEVEL] [--log-format text|json]
depwatch explain GROUP:ARTIFACT:VERSION --db DIR
depwatch version compare A B
depwatch version in-range V RANGE
depwatch db stats --db DIR
```

| Option | Meaning |
|---|---|
| `--db DIR` | Folder of OSV `*.json` records, searched recursively (each file holds one record or an array). |
| `--config FILE` | License policy, license exceptions and advisory suppressions (see below). |
| `--licenses FILE` | YAML map of `group:artifact` or `group:artifact:version` to an SPDX expression, for inputs without license data. |
| `--input-type` | Skip detection and read every input as this format. |
| `--fail-on` | Exit 1 if any unsuppressed finding is at or above this severity (default `low`; `none` never fails on findings). |
| `--include-dev` | Also check Maven `test` scope, Gradle configurations that all contain `test`, and CycloneDX `scope: excluded`. Skipped by default and counted in the report. |
| `-o, --output FILE` | Write the report to a file created with mode `0600`. An existing file is refused unless `--force`; a symbolic link is never written through. |
| `--max-file-size MIB` | Largest file read (inputs, config, each database file). Default 32. |
| `--follow-symlinks` | Follow symbolic links inside the `--db` folder. Off by default. |
| `--log-level`, `--log-format` | Diagnostics on stderr: `debug`, `info`, `warn` (default) or `error`, as text or one JSON object per line. |

Remember to quote ranges in the shell: `'[1.0,2.0)'`.

## Configuration

`config.example.yaml` (loaded with SnakeYAML's `SafeConstructor`; unknown keys are errors):

```yaml
licenses:
  allowed: [Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, ISC, EPL-2.0]
  review_required: [LGPL-2.1-only, LGPL-2.1-or-later, MPL-2.0, EPL-1.0]
  denied: [GPL-2.0-only, GPL-3.0-only, AGPL-3.0-only, SSPL-1.0]

exceptions:            # per-package license exceptions; reason is required
  - package: org.example:legacy-parser
    license: GPL-2.0-only            # optional: without it, any license is accepted
    reason: "Used only by the internal migration tool, which is never distributed (ticket EX-1042)."

suppressions:          # accepted advisories; reason is required
  - advisory: DEMO-2026-0006
    package: com.example:textutils   # optional
    reason: "Test-only dependency; the vulnerable word-wrap code path is never called."
```

License rules:

- SPDX ids match case-insensitively. A license on no list is **unknown**.
- `A OR B` takes the better outcome (you may pick either license); `A AND B` takes the worse (you must comply with both). `X WITH exception` is judged by `X`. `GPL-2.0+` is judged as written, or as `GPL-2.0-or-later` if only that is listed.
- Several `license` entries on one CycloneDX component are combined with `AND`, the conservative reading. A license given only by name becomes `LicenseRef-<name>`.
- Finding severities: denied = `high`, unknown or missing = `medium`, review required = `low`.
- License checks only run when license data exists (an SBOM, or `--licenses`); otherwise Depwatch says the policy was not applied rather than flagging every package as unknown.

## Sample output

All output below is copied from real runs of the commands shown, against the synthetic samples.

`depwatch scan samples/maven-app/pom.xml --db samples/osv-db`:

```
Depwatch 0.1.0 - offline dependency audit
Advisory DB: samples/osv-db (9 Maven advisories, 1 withdrawn, 0 skipped)
Input: samples/maven-app/pom.xml [pom] 7 checked, 1 dev skipped (use --include-dev)

SEVERITY   PACKAGE                 VERSION     FINDING           FIX / NOTE
CRITICAL   com.example:logkit      2.14.1      DEMO-2026-0001    2.16.0
HIGH       com.example:jsonmapper  2.10.1      DEMO-2026-0003    2.10.5.1
HIGH       org.example:http-core   4.5.13      DEMO-2026-0005    5.1.2 (major)
MEDIUM     com.example:widgets     1.0-rc1     DEMO-2026-0009    1.0
MEDIUM     org.example:yamlite     1.30        DEMO-2026-0004    none known

Details

[CRITICAL] DEMO-2026-0001  com.example:logkit:2.14.1  (samples/maven-app/pom.xml:46)
  Message template expansion in logkit can resolve attacker-controlled lookups
  why: 2.14.1 is in [2.0-beta9, 2.15.0) from DEMO-2026-0001 (introduced 2.0-beta9, fixed 2.15.0)
  severity: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H (base score 10.0)
  aliases: DEMO-ALIAS-LOGKIT-1
  fix: Upgrade to 2.16.0: the lowest recorded fix version above 2.14.1 that no known advisory affects, within the same major version (2.x). Skipped fix versions: 2.15.0 (still affected by DEMO-2026-0002).

[HIGH] DEMO-2026-0003  com.example:jsonmapper:2.10.1  (samples/maven-app/pom.xml:51)
  Polymorphic type handling in jsonmapper permits unsafe class instantiation
  why: 2.10.1 is in [2.10.0, 2.10.5.1) from DEMO-2026-0003 (introduced 2.10.0, fixed 2.10.5.1)
  severity: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H (base score 8.1)
  fix: Upgrade to 2.10.5.1: the lowest recorded fix version above 2.10.1 that no known advisory affects, within the same major version (2.x).

[HIGH] DEMO-2026-0005  org.example:http-core:4.5.13  (samples/maven-app/pom.xml:55)
  Request smuggling via ambiguous chunked encoding in http-core
  why: 4.5.13 is in (, 5.1.2) from DEMO-2026-0005 (introduced 0 (from the first version), fixed 5.1.2)
  severity: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N (base score 7.5)
  aliases: DEMO-ALIAS-HTTPCORE-7
  fix: No safe version is recorded in 4.x. The lowest safe version is 5.1.2, a major upgrade to 5.x.

[MEDIUM] DEMO-2026-0009  com.example:widgets:1.0-rc1  (samples/maven-app/pom.xml:64)
  Pre-release widgets builds render unescaped labels
  why: 1.0-rc1 is in [0.9, 1.0) from DEMO-2026-0009 (introduced 0.9, fixed 1.0)
  severity: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N (base score 6.1)
  fix: Upgrade to 1.0: the lowest recorded fix version above 1.0-rc1 that no known advisory affects, within the same major version (1.x).

[MEDIUM] DEMO-2026-0004  org.example:yamlite:1.30  (samples/maven-app/pom.xml:69)
  Unbounded alias expansion in yamlite can exhaust memory
  why: 1.30 is in (, 1.33] from DEMO-2026-0004 (introduced 0 (from the first version), last_affected 1.33)
  severity: database_specific.severity MODERATE
  fix: No version known to be safe is recorded in the advisory database. DEMO-2026-0004 affects versions up to and including 1.33 and names no fix; a later release may be safe, but none is named offline.

Summary: 7 dependencies checked, 5 findings (1 critical, 2 high, 2 medium)
```

Exit code: `1`.

`depwatch explain org.example:http-core:4.5.13 --db samples/osv-db` (shows a withdrawn advisory and a major-version upgrade):

```
org.example:http-core:4.5.13
Advisories naming org.example:http-core: 2 (of 9 Maven advisories in samples/osv-db)
Version canonical form: 4.5.13

  AFFECTED      DEMO-2026-0005  high     Request smuggling via ambiguous chunked encoding in http-core
                4.5.13 is in (, 5.1.2) from DEMO-2026-0005 (introduced 0 (from the first version), fixed 5.1.2)
                severity from: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N (base score 7.5)
  withdrawn     DEMO-2026-0007  high     WITHDRAWN: connection pool exhaustion in http-core (not a vulnerability)
                DEMO-2026-0007 was withdrawn on 2026-02-20T09:00:00Z and is ignored (it would otherwise match: 4.5.13 is in [4.5.0, 4.5.14) from DEMO-2026-0007 (introduced 4.5.0, fixed 4.5.14))
                severity from: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H (base score 7.5)

Verdict: 4.5.13 is affected by 1 advisory (DEMO-2026-0005).
Smallest safe upgrade: 5.1.2 (next major version)
  No safe version is recorded in 4.x. The lowest safe version is 5.1.2, a major upgrade to 5.x.
```

The version engine:

```
$ depwatch version compare 2.0-rc1 2.0
2.0-rc1 < 2.0
  2.0-rc1 -> canonical 2-rc-1
  2.0 -> canonical 2
$ depwatch version compare 1.0-alpha 1.0-a
1.0-alpha < 1.0-a
  1.0-alpha -> canonical 1-alpha
  1.0-a -> canonical 1-a
$ depwatch version in-range 2.0-rc1 '[1.0,2.0)'
2.0-rc1 is in [1.0,2.0) (matches [1.0,2.0))
  note: 2.0-rc1 < 2.0 because pre-release qualifiers sort before the release, so [1.0,2.0) includes it.
$ depwatch version in-range 1.1 '(,1.0],[1.2,)'
1.1 is not in (,1.0],[1.2,)
```

`depwatch db stats --db samples/osv-db`:

```
Advisory database: samples/osv-db
  files read:            10
  Maven advisories:      9 (1 withdrawn)
  skipped (malformed):   0
  non-Maven records:     1 (ignored)
  packages:              7
  by severity (active):  critical 1, high 4, medium 3, low 0, unknown 0
  with a fix version:    6
  without a fix version: 2
```

The XXE test fixture is rejected (exit code `2`):

```
$ depwatch scan src/test/resources/xxe/malicious-external-entity-pom.xml --db samples/osv-db
depwatch: error: src/test/resources/xxe/malicious-external-entity-pom.xml:3: DOCTYPE declarations are not allowed (XXE protection); file rejected without resolving any entity
Depwatch 0.1.0 - offline dependency audit
Advisory DB: samples/osv-db (9 Maven advisories, 1 withdrawn, 0 skipped)
Input: src/test/resources/xxe/malicious-external-entity-pom.xml (rejected: see diagnostics)

No findings.

Summary: 0 dependencies checked, 0 findings, 1 input(s) rejected
depwatch: error: 1 input file(s) were rejected; exiting with 2 so the gap is not missed
```

## Output formats & exit codes

| Format | Notes |
|---|---|
| `table` | Default. Summary table, then one block per finding with *why*, severity source and fix. |
| `json` | Schema `depwatch-report/1`, documented in [`docs/json-schema.md`](docs/json-schema.md). Deterministic: no timestamps, stable ordering. |
| `sarif` | SARIF 2.1.0. One rule per advisory or license rule; `level` is `error` for critical/high/unknown, `warning` for medium, `note` for low. Locations point at the input file (relative paths use `uriBaseId: SRCROOT`) and the line of the `<artifactId>` (POM), the lockfile entry, or the component's `purl` (SBOM, best effort). Suppressed findings carry `suppressions[]` with the justification. |
| `markdown` | For pull requests and tickets; untrusted text is escaped. |

A JSON finding, from `depwatch scan samples/sbom/app.cdx.json --db samples/osv-db --config config.example.yaml --format json` (abridged to the first finding):

```json
{
  "type": "vulnerability",
  "ruleId": "DEMO-2026-0001",
  "severity": "critical",
  "package": "com.example:logkit",
  "version": "2.14.1",
  "scope": "required",
  "origin": "components",
  "location": { "file": "samples/sbom/app.cdx.json", "line": 21 },
  "title": "Message template expansion in logkit can resolve attacker-controlled lookups",
  "why": "2.14.1 is in [2.0-beta9, 2.15.0) from DEMO-2026-0001 (introduced 2.0-beta9, fixed 2.15.0)",
  "advisory": {
    "id": "DEMO-2026-0001",
    "aliases": ["DEMO-ALIAS-LOGKIT-1"],
    "severitySource": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H (base score 10.0)",
    "matchedRange": "[2.0-beta9, 2.15.0)",
    "...": "..."
  },
  "fix": {
    "kind": "same-major",
    "version": "2.16.0",
    "explanation": "Upgrade to 2.16.0: the lowest recorded fix version above 2.14.1 that no known advisory affects, within the same major version (2.x). Skipped fix versions: 2.15.0 (still affected by DEMO-2026-0002)."
  },
  "license": null,
  "suppressed": false,
  "suppressionReason": null
}
```

| Command | Exit 0 | Exit 1 | Exit 2 |
|---|---|---|---|
| `scan` | no unsuppressed finding at or above `--fail-on` | at least one | usage, configuration or database error, or **any input file rejected** (the report is still written, so the gap is visible) |
| `explain` | not affected | affected | invalid coordinate or database error |
| `version compare` | compared | | invalid version |
| `version in-range` | in range | not in range | invalid version or range |
| `db stats` | loaded | | folder missing or without JSON files |

Errors are one line naming the file and the problem; Depwatch does not print stack traces.

## Testing

```bash
./gradlew build    # spotlessCheck + compile (-Xlint:all -Werror) + 419 JUnit 5 tests
```

The suite (JUnit 5 + AssertJ) covers:

- **Version ordering**: the 136-row cited table, both directions, `equals`/`hashCode`, canonical forms, transitivity, sorting a shuffled list, Maven's documented non-transitive case, validation of bad strings.
- **Ranges**: containment for the POM reference examples, unions, exclusive bounds, pre-release surprises, soft requirements, and twelve invalid specifications.
- **OSV semantics**: half-open `introduced`/`fixed`, inclusive `last_affected`, `introduced: 0`, multiple pairs in one range, unsorted events, `limit`, and a check that the explanatory intervals agree with the OSV algorithm on every probe.
- **Smallest safe upgrade**: same major, skipping still-affected fixes, preferring the current major, next major, "no safe version" (last_affected only, versions list only, unbounded advisory), withdrawn advisories, pre-release labelling.
- **Inputs**: POM properties, built-ins, managed versions, cycles, undefined and environment properties, ranges, BOM imports, line numbers; lockfile entries, malformed lines, dev detection, CRLF; SBOM purls, nested components, licenses, scopes, line numbers; purl decoding; format detection; size limits and invalid UTF-8.
- **XXE**: an external-entity fixture, a canary file that must never be read, billion laughs, an external DTD (rejected immediately, no fetch), XInclude not processed, and the parser features themselves.
- **License policy and config**: AND/OR/WITH/`+`, exceptions (and the rule that each needs a reason), suppressions, unknown keys, type errors, `SafeConstructor` refusing Java tags, alias bombs, duplicate keys.
- **CLI**: every exit code, `--fail-on` thresholds, suppressions, `--output` mode `0600`, overwrite refusal, symlink refusal, `--include-dev`, JSON logging, `explain`, `version`, `db stats`, help and version.
- **Reports**: JSON fields and determinism, SARIF structure (rule indexes, levels, locations, fingerprints, suppressions), table and Markdown content and escaping.
- **Sample regression**: the exact findings for all three samples with the example config.

## Performance notes

Measured once on an Apple M2 with a generated database of 20,000 one-record OSV files (5,000 packages) and a 2,000-entry lockfile: `db stats` took 10.8 s wall clock on the first (cold-cache) run and `scan` of the lockfile took 7.2 s wall clock, both including JVM start. Loading the folder (one file read and JSON parse per record) dominates; matching is an index lookup per dependency. These are single measurements, not a benchmark.

## Limitations

- **No real advisory data was used in testing.** The samples and the performance run are synthetic. The loader follows the OSV schema and has been tested with valid and malformed records, but a full real export may contain shapes not seen here.
- **No dependency resolution.** Depwatch reads what the file declares. It does not fetch parent POMs or imported BOMs, does not compute transitive dependencies from a POM, does not evaluate Maven profiles, and does not pick a version for a POM version range. Use a lockfile or an SBOM for resolved, transitive dependencies.
- **Upgrade candidates come from the advisories.** Offline there is no list of published releases, so "smallest safe upgrade" means the lowest *fix version named in the advisory data* that no advisory affects. A release between fixes that is also safe is not known to Depwatch.
- **CVSS v4 is not scored.** A record with only a CVSS v4 vector and no `database_specific.severity` is `unknown` (treated as `high` for `--fail-on`). CVSS v2 is ignored.
- **Package names match exactly** (`group:artifact`, case-sensitive), as in Maven and OSV.
- **`versions` lists match by Maven equality**, so a listed `1.10` also matches `1.10.0`.
- Line numbers in SBOMs are best effort (the line where the purl text appears).
- Version strings with whitespace, control characters or `[](),` are rejected, which is stricter than Maven.
- Windows is not covered by CI.

## Roadmap

- `--known-versions` input (for example a Maven metadata file you download yourself) so the safe-upgrade search can consider every published release, not only fix versions.
- CVSS v4 base scoring.
- Gradle version catalogs (`libs.versions.toml`) and SPDX SBOMs as inputs.
- Reading the OSV `all.zip` archive directly, without unzipping.
- A `diff` mode that reports only findings introduced between two inputs.

## Ethical use

Depwatch is a defensive tool for auditing software you build, maintain or are authorized to assess. It only reads local files. The bundled advisory data is fictional and must not be used for real security decisions; use a real advisory source for that, and verify important results against the advisory's own references.

## License

MIT. See [`LICENSE`](LICENSE).
