package io.github.arjunpotluri7spec.depwatch.advisory;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.arjunpotluri7spec.depwatch.TestData;
import io.github.arjunpotluri7spec.depwatch.model.Coordinate;
import io.github.arjunpotluri7spec.depwatch.model.Diagnostic;
import io.github.arjunpotluri7spec.depwatch.model.Severity;
import io.github.arjunpotluri7spec.depwatch.util.DepwatchException;
import io.github.arjunpotluri7spec.depwatch.util.Limits;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class OsvLoaderTest {

  @TempDir Path dir;

  @TempDir Path outside;

  private static final String GOOD =
      """
      {"id": "TEST-1", "modified": "2026-01-01T00:00:00Z", "summary": "s",
       "affected": [{"package": {"ecosystem": "Maven", "name": "com.example:a"},
                     "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"fixed": "1.2"}]}]}]}
      """;

  private AdvisoryDatabase load() {
    return OsvLoader.load(dir, Limits.defaults());
  }

  private void write(String name, String json) throws IOException {
    Files.writeString(dir.resolve(name), json);
  }

  @Test
  void loadsTheSampleDatabase() {
    AdvisoryDatabase db = OsvLoader.load(TestData.SAMPLE_DB, Limits.defaults());
    AdvisoryDatabase.Stats s = db.stats();
    assertThat(s.filesRead()).isEqualTo(10);
    assertThat(s.recordsLoaded()).isEqualTo(9);
    assertThat(s.withdrawn()).isEqualTo(1);
    assertThat(s.nonMavenRecords()).isEqualTo(1);
    assertThat(s.recordsSkipped()).isZero();
    assertThat(db.diagnostics()).isEmpty();
    assertThat(db.forPackage(Coordinate.parse("com.example:logkit")))
        .extracting(Advisory::id)
        .containsExactly("DEMO-2026-0001", "DEMO-2026-0002");
  }

  @Test
  void sampleDatabaseContainsNoRealIdentifiers() {
    AdvisoryDatabase db = OsvLoader.load(TestData.SAMPLE_DB, Limits.defaults());
    for (Advisory a : db.advisories()) {
      assertThat(a.id()).startsWith("DEMO-");
      assertThat(a.aliases()).noneMatch(x -> x.startsWith("CVE-") || x.startsWith("GHSA-"));
      assertThat(a.affected())
          .allMatch(
              p ->
                  p.coordinate().groupId().startsWith("com.example")
                      || p.coordinate().groupId().startsWith("org.example"));
    }
  }

  @Test
  void severityPrecedence() {
    AdvisoryDatabase db = OsvLoader.load(TestData.SAMPLE_DB, Limits.defaults());
    Advisory cvss = byId(db, "DEMO-2026-0001");
    assertThat(cvss.severity()).isEqualTo(Severity.CRITICAL);
    assertThat(cvss.severitySource()).contains("base score 10.0");
    Advisory label = byId(db, "DEMO-2026-0004");
    assertThat(label.severity()).isEqualTo(Severity.MEDIUM);
    assertThat(label.severitySource()).isEqualTo("database_specific.severity MODERATE");
  }

  @Test
  void databaseSpecificSeverityWinsOverCvss() throws IOException {
    write(
        "a.json",
        GOOD.replace(
            "\"summary\": \"s\",",
            "\"summary\": \"s\", \"database_specific\": {\"severity\": \"LOW\"},"
                + " \"severity\": [{\"type\": \"CVSS_V3\", \"score\":"
                + " \"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\"}],"));
    assertThat(load().advisories().get(0).severity()).isEqualTo(Severity.LOW);
  }

  @Test
  void cvssV4OnlyIsUnknown() throws IOException {
    write(
        "a.json",
        GOOD.replace(
            "\"summary\": \"s\",",
            "\"summary\": \"s\", \"severity\": [{\"type\": \"CVSS_V4\", \"score\":"
                + " \"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N\"}],"));
    Advisory a = load().advisories().get(0);
    assertThat(a.severity()).isEqualTo(Severity.UNKNOWN);
    assertThat(a.severitySource()).contains("v4");
  }

  @Test
  void malformedRecordsAreSkippedWithWarnings() throws IOException {
    write("good.json", GOOD);
    write("not-json.json", "{ this is not json");
    write("no-id.json", GOOD.replace("\"id\": \"TEST-1\",", ""));
    write("bad-version.json", GOOD.replace("TEST-1", "TEST-2").replace("\"1.2\"", "\"1 2\""));
    write("bad-event.json", GOOD.replace("TEST-1", "TEST-3").replace("\"fixed\"", "\"patched\""));
    write(
        "no-introduced.json",
        GOOD.replace("TEST-1", "TEST-4").replace("{\"introduced\": \"1.0\"}, ", ""));
    write("bad-name.json", GOOD.replace("TEST-1", "TEST-5").replace("com.example:a", "no-colon"));
    write("not-object.json", "[1, 2]");
    write(
        "two-keys.json",
        GOOD.replace("TEST-1", "TEST-6")
            .replace("{\"fixed\": \"1.2\"}", "{\"fixed\": \"1.2\", \"limit\": \"2\"}"));
    AdvisoryDatabase db = load();
    assertThat(db.advisories()).extracting(Advisory::id).containsExactly("TEST-1");
    assertThat(db.stats().recordsSkipped()).isEqualTo(9);
    assertThat(db.diagnostics())
        .extracting(Diagnostic::render)
        .anyMatch(m -> m.contains("not-json.json") && m.contains("invalid JSON"))
        .anyMatch(m -> m.contains("missing 'id'"))
        .anyMatch(m -> m.contains("TEST-2") && m.contains("whitespace"))
        .anyMatch(m -> m.contains("TEST-3") && m.contains("unknown range event"))
        .anyMatch(m -> m.contains("TEST-4") && m.contains("no 'introduced' event"))
        .anyMatch(m -> m.contains("TEST-5") && m.contains("group:artifact"))
        .anyMatch(m -> m.contains("TEST-6") && m.contains("exactly one key"));
  }

  @Test
  void duplicateIdsKeepTheFirstFile() throws IOException {
    write("a.json", GOOD);
    write("b.json", GOOD);
    AdvisoryDatabase db = load();
    assertThat(db.advisories()).hasSize(1);
    assertThat(db.diagnostics())
        .anyMatch(d -> d.message().contains("duplicate advisory id TEST-1"));
  }

  @Test
  void arrayFilesAndNestedDirectoriesAreLoaded() throws IOException {
    Files.createDirectories(dir.resolve("maven/sub"));
    Files.writeString(
        dir.resolve("maven/sub/all.json"),
        "[" + GOOD + "," + GOOD.replace("TEST-1", "TEST-9") + "]");
    assertThat(load().advisories()).extracting(Advisory::id).containsExactly("TEST-1", "TEST-9");
  }

  @Test
  void versionsListAndWithdrawnAreParsed() throws IOException {
    write(
        "v.json",
        """
        {"id": "TEST-7", "withdrawn": "2026-02-01T00:00:00Z",
         "affected": [{"package": {"ecosystem": "Maven", "name": "com.example:b"}, "versions": ["1.0", "1.1"]}]}
        """);
    Advisory a = load().advisories().get(0);
    assertThat(a.isWithdrawn()).isTrue();
    assertThat(a.affected().get(0).versions()).hasSize(2);
  }

  @Test
  void nonMavenAndSemverAreIgnored() throws IOException {
    write(
        "npm.json",
        """
        {"id": "TEST-8", "affected": [{"package": {"ecosystem": "npm", "name": "x"},
          "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]}
        """);
    write("good.json", GOOD);
    AdvisoryDatabase db = load();
    assertThat(db.advisories()).extracting(Advisory::id).containsExactly("TEST-1");
    assertThat(db.stats().nonMavenRecords()).isEqualTo(1);
  }

  @Test
  void missingOrEmptyDirectoryIsAnError() throws IOException {
    assertThatThrownBy(() -> OsvLoader.load(dir.resolve("nope"), Limits.defaults()))
        .isInstanceOf(DepwatchException.class)
        .hasMessageContaining("not found");
    Files.writeString(dir.resolve("readme.txt"), "no json here");
    assertThatThrownBy(this::load)
        .isInstanceOf(DepwatchException.class)
        .hasMessageContaining("no *.json advisory files");
  }

  @Test
  void oversizedFilesAreSkipped() throws IOException {
    write("good.json", GOOD);
    write("big.json", GOOD.replace("TEST-1", "TEST-2") + " ".repeat(5000));
    AdvisoryDatabase db = OsvLoader.load(dir, new Limits(2000, 100, false));
    assertThat(db.advisories()).extracting(Advisory::id).containsExactly("TEST-1");
    assertThat(db.diagnostics()).anyMatch(d -> d.message().contains("larger than the limit"));
  }

  @Test
  void symlinksAreNotFollowedByDefault() throws IOException {
    Path target = outside.resolve("x.json");
    Files.writeString(target, GOOD.replace("TEST-1", "TEST-LINK"));
    write("good.json", GOOD);
    try {
      Files.createSymbolicLink(dir.resolve("link.json"), target);
    } catch (UnsupportedOperationException | IOException e) {
      return; // file system without symlinks
    }
    assertThat(load().advisories()).extracting(Advisory::id).containsExactly("TEST-1");
    assertThat(OsvLoader.load(dir, new Limits(1 << 20, 100, true)).advisories())
        .extracting(Advisory::id)
        .contains("TEST-LINK");
  }

  private static Advisory byId(AdvisoryDatabase db, String id) {
    return db.advisories().stream().filter(a -> a.id().equals(id)).findFirst().orElseThrow();
  }
}
