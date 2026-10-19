# Samples (synthetic data)

**Everything in this folder is invented.** The packages (`com.example:*`, `org.example:*`),
advisory IDs (`DEMO-2026-NNNN`), summaries, scores and URLs are fictional and exist only to
demonstrate Depwatch. None of it describes a real vulnerability, and no real CVE or GHSA
identifier appears anywhere. Do not use this data to make security decisions.

| Path | What it shows |
|---|---|
| `maven-app/pom.xml` | `<properties>` with nested `${...}` interpolation, `${revision}` / `${project.version}`, versions taken from `<dependencyManagement>`, a `<parent>` that is recorded but not resolved, a `1.0-rc1` pre-release, and a `test`-scope dependency that is skipped unless `--include-dev` |
| `gradle-app/gradle.lockfile` | Gradle lockfile entries, a test-only configuration, and an `empty=` line |
| `sbom/app.cdx.json` | CycloneDX 1.6 JSON with purls, license ids, an `OR` expression, a component with no license, a nested component, an `excluded` (dev) component and a non-Maven component |
| `licenses.example.yaml` | License data for `--licenses`, for inputs that carry none |
| `osv-db/` | Ten fictional OSV records, described below |

## The fictional advisory database

| ID | Package | Demonstrates |
|---|---|---|
| DEMO-2026-0001 | com.example:logkit | `introduced` / `fixed`, CVSS v3.1 vector (critical) |
| DEMO-2026-0002 | com.example:logkit | an incomplete fix: 2.15.0 is still affected, so the smallest safe upgrade skips it |
| DEMO-2026-0003 | com.example:jsonmapper | three introduced/fixed pairs in one range (one fix per release line) |
| DEMO-2026-0004 | org.example:yamlite | `introduced: 0` + `last_affected` with no fix, so no safe version is known |
| DEMO-2026-0005 | org.example:http-core | no fix in 4.x: the smallest safe upgrade is a major-version change |
| DEMO-2026-0006 | com.example:textutils | an explicit `versions` list instead of a range |
| DEMO-2026-0007 | org.example:http-core | a `withdrawn` advisory: shown by `explain`, never reported |
| DEMO-2026-0008 | org.example:cachebox | severity from `database_specific.severity` |
| DEMO-2026-0009 | com.example:widgets | `1.0-rc1 < 1.0`: a release candidate inside `[0.9, 1.0)` |
| DEMO-2026-0010 | example-merge (npm) | a non-Maven record that is counted and ignored |

To scan with real data, download an OSV export for the Maven ecosystem yourself (see the main
README) and point `--db` at the unzipped folder.
