# JSON report schema: `depwatch-report/1`

`depwatch scan --format json` writes one JSON object. Within schema version 1, fields are only
ever added, never renamed or removed. Output is deterministic: there are no timestamps, and
findings are sorted by severity (critical, high, unknown, medium, low), then type
(vulnerabilities before licenses), package, version, rule id and location.

## Top level

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | Always `depwatch-report/1`. |
| `tool` | object | `name` (`depwatch`) and `version`. |
| `database` | object | `location`, `advisories` (Maven records loaded, including withdrawn), `withdrawn`, `skipped` (malformed records). |
| `inputs` | array | One object per input file, see below. |
| `summary` | object | See below. |
| `findings` | array | See below. |
| `diagnostics` | array | Warnings and errors met while reading the database, inputs and configuration. |

## `inputs[]`

| Field | Type | Meaning |
|---|---|---|
| `file` | string | Path as given on the command line. |
| `format` | string or null | `pom`, `gradle-lockfile` or `cyclonedx`; null if the file was rejected before detection. |
| `dependencies` | integer | Dependencies read from the file. |
| `checked` | integer | Dependencies checked (excludes dev dependencies unless `--include-dev`). |
| `devSkipped` | integer | Dev dependencies skipped. |
| `unresolved` | integer | Entries that could not be used (unresolved version, malformed line, component without purl, ...). |
| `error` | string or null | Why the whole file was rejected, if it was. |

## `summary`

| Field | Type | Meaning |
|---|---|---|
| `dependenciesChecked` | integer | Sum of `inputs[].checked`. |
| `findings` | integer | Unsuppressed findings. |
| `suppressed` | integer | Findings accepted by a configured suppression. |
| `bySeverity` | object | Unsuppressed counts for `critical`, `high`, `unknown`, `medium`, `low`. |
| `licenseChecks` | boolean | Whether the license policy was applied to at least one input. |
| `includeDev` | boolean | Whether `--include-dev` was given. |
| `rejectedInputs` | integer | Input files rejected as a whole (these make the exit code 2). |

## `findings[]`

| Field | Type | Meaning |
|---|---|---|
| `type` | string | `vulnerability` or `license`. |
| `ruleId` | string | The advisory id, or `license-denied`, `license-unknown`, `license-review`. |
| `severity` | string | `critical`, `high`, `unknown`, `medium` or `low`. |
| `package` | string | `group:artifact`. |
| `version` | string | The version as written in the input. |
| `scope` | string | Maven scope, Gradle configurations, or CycloneDX scope. |
| `origin` | string | `dependencies`, `dependencyManagement`, `dependencies (version from dependencyManagement)`, `lockfile` or `components`. |
| `location` | object | `file` and `line` (null when unknown). |
| `title` | string | Advisory summary, or a license finding title. |
| `why` | string | One sentence explaining the finding with real values. |
| `advisory` | object or null | For vulnerabilities: `id`, `aliases`, `summary`, `severitySource`, `matchedRange` (interval notation or `versions list`), `modified`, `source` (database file), `references[]` (`type`, `url`). |
| `fix` | object or null | For vulnerabilities: `kind` (`same-major`, `next-major`, `none-known`), `version` (null for `none-known`) and `explanation`. |
| `license` | object or null | For license findings: `status` (`denied`, `unknown`, `review`), `expression` (null when the package has no license data) and `explanation`. |
| `suppressed` | boolean | True when a configured suppression accepted the finding. |
| `suppressionReason` | string or null | The suppression's reason. |

## `diagnostics[]`

| Field | Type | Meaning |
|---|---|---|
| `level` | string | `info`, `warn` or `error`. |
| `file` | string or null | File concerned, if known. |
| `line` | integer or null | Line, if known. |
| `message` | string | One-line description. |
