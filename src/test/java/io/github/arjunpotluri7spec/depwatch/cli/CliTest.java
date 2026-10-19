package io.github.arjunpotluri7spec.depwatch.cli;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.arjunpotluri7spec.depwatch.util.Json;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class CliTest {

  @TempDir Path dir;

  private static final String POM = "samples/maven-app/pom.xml";
  private static final String LOCK = "samples/gradle-app/gradle.lockfile";
  private static final String SBOM = "samples/sbom/app.cdx.json";
  private static final String DB = "samples/osv-db";

  record Run(int code, String out, String err) {}

  private static Run run(String... args) {
    StringWriter out = new StringWriter();
    StringWriter err = new StringWriter();
    int code = Main.run(args, new PrintWriter(out, true), new PrintWriter(err, true));
    return new Run(code, out.toString(), err.toString());
  }

  @Test
  void scanWithFindingsExitsOne() {
    Run r = run("scan", POM, "--db", DB);
    assertThat(r.code()).isEqualTo(ExitCodes.FINDINGS);
    assertThat(r.out()).contains("DEMO-2026-0001").contains("Summary:");
    assertThat(r.err()).isEmpty();
  }

  @Test
  void failOnThresholds() {
    assertThat(run("scan", POM, "--db", DB, "--fail-on", "none").code()).isEqualTo(ExitCodes.OK);
    assertThat(run("scan", POM, "--db", DB, "--fail-on", "critical").code())
        .isEqualTo(ExitCodes.FINDINGS);
    assertThat(run("scan", LOCK, "--db", DB, "--fail-on", "critical").code())
        .isEqualTo(ExitCodes.OK);
    assertThat(run("scan", LOCK, "--db", DB, "--fail-on", "HIGH").code())
        .isEqualTo(ExitCodes.FINDINGS);
  }

  @Test
  void suppressedFindingsDoNotFail() throws IOException {
    Path lock = dir.resolve("gradle.lockfile");
    Files.writeString(lock, "com.example:textutils:1.9=runtimeClasspath\n");
    assertThat(run("scan", lock.toString(), "--db", DB).code()).isEqualTo(ExitCodes.FINDINGS);
    assertThat(run("scan", lock.toString(), "--db", DB, "--config", "config.example.yaml").code())
        .isEqualTo(ExitCodes.OK);
  }

  @Test
  void cleanInputExitsZero() throws IOException {
    Path lock = dir.resolve("gradle.lockfile");
    Files.writeString(lock, "com.example:logkit:2.16.0=runtimeClasspath\n");
    Run r = run("scan", lock.toString(), "--db", DB);
    assertThat(r.code()).isEqualTo(ExitCodes.OK);
    assertThat(r.out()).contains("No findings.");
  }

  @Test
  void usageAndInputErrorsExitTwo() {
    assertThat(run("scan", POM).code()).isEqualTo(ExitCodes.ERROR); // --db missing
    assertThat(run("scan", "--db", DB).code()).isEqualTo(ExitCodes.ERROR); // no input
    assertThat(run("scan", POM, "--db", "no/such/dir").err())
        .contains("advisory database directory not found");
    assertThat(run("scan", POM, "--db", DB, "--format", "xml").code()).isEqualTo(ExitCodes.ERROR);
    assertThat(run("scan", POM, "--db", DB, "--fail-on", "severe").code())
        .isEqualTo(ExitCodes.ERROR);
    assertThat(run("scan", POM, "--db", DB, "--input-type", "npm").err())
        .contains("--input-type must be");
    assertThat(run("scan", POM, "--db", DB, "--bogus").code()).isEqualTo(ExitCodes.ERROR);
    assertThat(run().code()).isEqualTo(ExitCodes.ERROR);
  }

  @Test
  void missingInputFileExitsTwoWithOneLineError() {
    Run r = run("scan", "missing/pom.xml", "--db", DB);
    assertThat(r.code()).isEqualTo(ExitCodes.ERROR);
    assertThat(r.err())
        .contains("missing/pom.xml: file not found")
        .doesNotContain("Exception")
        .doesNotContain("\tat ");
  }

  @Test
  void xxePomIsRejectedWithExitTwo() {
    Run r = run("scan", "src/test/resources/xxe/malicious-external-entity-pom.xml", "--db", DB);
    assertThat(r.code()).isEqualTo(ExitCodes.ERROR);
    assertThat(r.err()).contains("DOCTYPE declarations are not allowed (XXE protection)");
    assertThat(r.out()).contains("rejected");
    assertThat(r.err()).doesNotContain("root:");
  }

  @Test
  void invalidConfigExitsTwo() throws IOException {
    Path cfg = dir.resolve("bad.yaml");
    Files.writeString(cfg, "licenses: {allowed: [MIT]}\nexceptions:\n  - package: org.example:x\n");
    Run r = run("scan", POM, "--db", DB, "--config", cfg.toString());
    assertThat(r.code()).isEqualTo(ExitCodes.ERROR);
    assertThat(r.err()).contains("reason is required");
  }

  @Test
  void jsonAndSarifFormatsAreValidJson() {
    JsonNode json =
        Json.parse(
            run("scan", SBOM, "--db", DB, "--format", "json", "--config", "config.example.yaml")
                .out(),
            "out");
    assertThat(json.path("schema").asText()).isEqualTo("depwatch-report/1");
    JsonNode sarif = Json.parse(run("scan", SBOM, "--db", DB, "--format", "sarif").out(), "out");
    assertThat(sarif.path("version").asText()).isEqualTo("2.1.0");
    assertThat(run("scan", SBOM, "--db", DB, "--format", "markdown").out())
        .startsWith("# Depwatch report");
  }

  @Test
  void outputFileIsPrivateAndNotOverwrittenWithoutForce() throws IOException {
    Path report = dir.resolve("report.json");
    Run first = run("scan", POM, "--db", DB, "--format", "json", "--output", report.toString());
    assertThat(first.code()).isEqualTo(ExitCodes.FINDINGS);
    assertThat(first.out()).isEmpty();
    assertThat(Files.readString(report)).contains("depwatch-report/1");
    if (Files.getFileStore(dir).supportsFileAttributeView("posix")) {
      assertThat(PosixFilePermissions.toString(Files.getPosixFilePermissions(report)))
          .isEqualTo("rw-------");
    }
    Run second = run("scan", POM, "--db", DB, "--output", report.toString());
    assertThat(second.code()).isEqualTo(ExitCodes.ERROR);
    assertThat(second.err()).contains("file exists (use --force to overwrite)");
    Run forced = run("scan", POM, "--db", DB, "--output", report.toString(), "--force");
    assertThat(forced.code()).isEqualTo(ExitCodes.FINDINGS);
    assertThat(Files.readString(report)).startsWith("Depwatch");
  }

  @Test
  void outputThroughSymlinkIsRefused() throws IOException {
    Path target = dir.resolve("target.txt");
    Files.writeString(target, "keep");
    Path link = dir.resolve("link.txt");
    try {
      Files.createSymbolicLink(link, target);
    } catch (UnsupportedOperationException | IOException e) {
      return;
    }
    Run r = run("scan", POM, "--db", DB, "--output", link.toString(), "--force");
    assertThat(r.code()).isEqualTo(ExitCodes.ERROR);
    assertThat(r.err()).contains("symbolic link");
    assertThat(Files.readString(target)).isEqualTo("keep");
  }

  @Test
  void includeDevAddsTestScopeDependencies() {
    assertThat(run("scan", POM, "--db", DB).out()).doesNotContain("textutils");
    assertThat(run("scan", POM, "--db", DB, "--include-dev").out())
        .contains("com.example:textutils");
  }

  @Test
  void jsonLogFormatEmitsOneObjectPerLine() {
    Run r = run("scan", POM, "--db", DB, "--log-level", "info", "--log-format", "json");
    String[] lines = r.err().strip().split("\n");
    assertThat(lines).isNotEmpty();
    for (String line : lines) {
      JsonNode n = Json.parse(line, "log");
      assertThat(n.path("level").asText()).isIn("info", "warn", "error");
      assertThat(n.has("msg")).isTrue();
    }
  }

  @Test
  void explainShowsEveryAdvisoryAndTheUpgrade() {
    Run r = run("explain", "com.example:logkit:2.14.1", "--db", DB);
    assertThat(r.code()).isEqualTo(ExitCodes.FINDINGS);
    assertThat(r.out())
        .contains("AFFECTED      DEMO-2026-0001")
        .contains("not affected  DEMO-2026-0002")
        .contains("2.14.1 is in [2.0-beta9, 2.15.0) from DEMO-2026-0001")
        .contains("Smallest safe upgrade: 2.16.0 (same major version)");
    Run safe = run("explain", "com.example:logkit:2.16.0", "--db", DB);
    assertThat(safe.code()).isEqualTo(ExitCodes.OK);
    assertThat(safe.out()).contains("is not affected by any known advisory");
    Run withdrawn = run("explain", "org.example:http-core:4.5.13", "--db", DB);
    assertThat(withdrawn.out()).contains("withdrawn").contains("(next major version)");
    Run none = run("explain", "org.example:yamlite:1.30", "--db", DB);
    assertThat(none.out()).contains("Smallest safe upgrade: none known");
    Run unknownPkg = run("explain", "org.example:nothing:1.0", "--db", DB);
    assertThat(unknownPkg.code()).isEqualTo(ExitCodes.OK);
    assertThat(unknownPkg.out()).contains("No advisory in the database names org.example:nothing");
    assertThat(run("explain", "not-a-gav", "--db", DB).code()).isEqualTo(ExitCodes.ERROR);
  }

  @Test
  void versionCompare() {
    Run eq = run("version", "compare", "1.0", "1.0.0");
    assertThat(eq.code()).isEqualTo(ExitCodes.OK);
    assertThat(eq.out()).startsWith("1.0 == 1.0.0");
    assertThat(run("version", "compare", "2.0-rc1", "2.0").out()).startsWith("2.0-rc1 < 2.0");
    assertThat(run("version", "compare", "1-sp", "1").out()).startsWith("1-sp > 1");
    assertThat(run("version", "compare", "1 0", "1").code()).isEqualTo(ExitCodes.ERROR);
  }

  @Test
  void versionInRange() {
    Run in = run("version", "in-range", "2.0-rc1", "[1.0,2.0)");
    assertThat(in.code()).isEqualTo(ExitCodes.OK);
    assertThat(in.out())
        .contains("is in [1.0,2.0)")
        .contains("pre-release qualifiers sort before the release");
    assertThat(run("version", "in-range", "2.0", "[1.0,2.0)").code()).isEqualTo(ExitCodes.FINDINGS);
    assertThat(run("version", "in-range", "1.5", "(,1.0],[1.2,)").code()).isEqualTo(ExitCodes.OK);
    assertThat(run("version", "in-range", "1.0", "(1.0)").code()).isEqualTo(ExitCodes.ERROR);
    assertThat(run("version", "in-range", "9", "1.0").out()).contains("soft requirement");
  }

  @Test
  void dbStats() {
    Run r = run("db", "stats", "--db", DB);
    assertThat(r.code()).isEqualTo(ExitCodes.OK);
    assertThat(r.out())
        .contains("Maven advisories:      9 (1 withdrawn)")
        .contains("non-Maven records:     1");
    assertThat(run("db", "stats", "--db", dir.toString()).code()).isEqualTo(ExitCodes.ERROR);
  }

  @Test
  void helpAndVersion() {
    Run help = run("scan", "--help");
    assertThat(help.code()).isEqualTo(ExitCodes.OK);
    assertThat(help.out()).contains("--fail-on").contains("Exit codes");
    Run version = run("--version");
    assertThat(version.code()).isEqualTo(ExitCodes.OK);
    assertThat(version.out()).startsWith("depwatch ");
  }
}
