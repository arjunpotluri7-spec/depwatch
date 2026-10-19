# Contributing to Depwatch

Thanks for helping. Bug reports, test cases and focused pull requests are all welcome.

## Development setup

You need JDK 17. The Gradle wrapper downloads the pinned Gradle version (checksum-verified).

```bash
./gradlew build          # spotlessCheck, compile with -Xlint:all -Werror, tests
./gradlew spotlessApply  # format with google-java-format
./gradlew installDist    # build/install/depwatch/bin/depwatch
```

## Ground rules

- **Stay offline and read-only.** No network calls, no subprocesses, nothing that executes or
  loads the files being analyzed. `ArchitectureTest` checks for network and process APIs.
- **Keep the library free of CLI code.** Only `cli/` may use picocli.
- **Explain, don't just flag.** New findings need a `why` sentence that uses the real values.
- **Synthetic data only.** Test data and samples use `com.example` / `org.example` packages,
  `DEMO-` advisory ids, documentation IP ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
  and example.com/org/net domains. Never add real CVE or GHSA ids, real personal data, or any
  string shaped like a real credential.
- **Version engine changes need table rows.** Add cases to
  `src/test/resources/version-order-cases.csv` with a comment citing where the expected order
  comes from (Maven documentation or Maven's observed behavior).

## Dependencies

Versions live in `gradle/libs.versions.toml` and are locked in `gradle.lockfile`. After changing
a dependency, regenerate the lock state and commit it:

```bash
./gradlew dependencies --write-locks
```

## Pull requests

- One topic per pull request, with tests.
- `./gradlew build` must pass locally.
- Describe user-visible changes (new options, report fields, exit codes) in the pull request and
  update the README and `docs/json-schema.md` when they change.
