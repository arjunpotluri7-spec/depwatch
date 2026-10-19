package io.github.arjunpotluri7spec.depwatch.report;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.arjunpotluri7spec.depwatch.scan.ScanFixtures;
import io.github.arjunpotluri7spec.depwatch.scan.ScanResult;
import io.github.arjunpotluri7spec.depwatch.util.Json;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;

class ReportFormatsTest {

  private static final ScanResult RESULT = ScanFixtures.allSamples();

  @Test
  void jsonReportHasTheDocumentedShape() {
    JsonNode root = Json.parse(JsonReport.render(RESULT), "report.json");
    assertThat(root.path("schema").asText()).isEqualTo("depwatch-report/1");
    assertThat(root.path("tool").path("name").asText()).isEqualTo("depwatch");
    assertThat(root.path("inputs")).hasSize(3);
    assertThat(root.path("summary").path("findings").asInt()).isEqualTo(12);
    assertThat(root.path("summary").path("suppressed").asInt()).isEqualTo(3);
    assertThat(root.path("summary").path("bySeverity").path("critical").asInt()).isEqualTo(2);
    JsonNode first = root.path("findings").get(0);
    for (String field :
        new String[] {
          "type",
          "ruleId",
          "severity",
          "package",
          "version",
          "scope",
          "origin",
          "location",
          "title",
          "why",
          "advisory",
          "fix",
          "license",
          "suppressed",
          "suppressionReason"
        }) {
      assertThat(first.has(field)).as(field).isTrue();
    }
    assertThat(first.path("type").asText()).isEqualTo("vulnerability");
    assertThat(first.path("location").path("line").asInt()).isEqualTo(46);
    assertThat(first.path("advisory").path("matchedRange").asText())
        .isEqualTo("[2.0-beta9, 2.15.0)");
    assertThat(first.path("fix").path("kind").asText()).isEqualTo("same-major");
    assertThat(first.path("fix").path("version").asText()).isEqualTo("2.16.0");
    JsonNode license = null;
    for (JsonNode f : root.path("findings")) {
      if (f.path("type").asText().equals("license")) {
        license = f;
        break;
      }
    }
    assertThat(license).isNotNull();
    assertThat(license.path("license").path("status").asText()).isEqualTo("denied");
    assertThat(license.path("advisory").isNull()).isTrue();
  }

  @Test
  void jsonOutputIsDeterministic() {
    assertThat(JsonReport.render(ScanFixtures.allSamples())).isEqualTo(JsonReport.render(RESULT));
  }

  @Test
  void sarifReportIsValidSarif210Structure() {
    JsonNode root = Json.parse(SarifReport.render(RESULT), "report.sarif");
    assertThat(root.path("version").asText()).isEqualTo("2.1.0");
    assertThat(root.path("$schema").asText()).contains("sarif-2.1.0");
    assertThat(root.path("runs")).hasSize(1);
    JsonNode run = root.path("runs").get(0);
    JsonNode driver = run.path("tool").path("driver");
    assertThat(driver.path("name").asText()).isEqualTo("depwatch");
    JsonNode rules = driver.path("rules");
    Set<String> ruleIds = new HashSet<>();
    rules.forEach(r -> ruleIds.add(r.path("id").asText()));
    assertThat(ruleIds).hasSize(rules.size()).contains("DEMO-2026-0001", "license-denied");
    JsonNode results = run.path("results");
    assertThat(results).hasSize(RESULT.findings().size());
    for (JsonNode res : results) {
      String ruleId = res.path("ruleId").asText();
      int index = res.path("ruleIndex").asInt();
      assertThat(rules.get(index).path("id").asText()).isEqualTo(ruleId);
      assertThat(res.path("level").asText()).isIn("error", "warning", "note");
      assertThat(res.path("message").path("text").asText()).isNotBlank();
      JsonNode phys = res.path("locations").get(0).path("physicalLocation");
      assertThat(phys.path("artifactLocation").path("uri").asText()).startsWith("samples/");
      assertThat(phys.path("artifactLocation").path("uriBaseId").asText()).isEqualTo("SRCROOT");
      assertThat(phys.path("region").path("startLine").asInt()).isPositive();
      assertThat(res.path("partialFingerprints").path("depwatchFinding/v1").asText()).hasSize(32);
    }
    long suppressed = 0;
    for (JsonNode res : results) {
      if (res.has("suppressions")) {
        suppressed++;
        assertThat(res.path("suppressions").get(0).path("justification").asText()).isNotBlank();
      }
    }
    assertThat(suppressed).isEqualTo(3);
  }

  @Test
  void sarifLevelsAndUris() {
    assertThat(SarifReport.level(io.github.arjunpotluri7spec.depwatch.model.Severity.UNKNOWN))
        .isEqualTo("error");
    assertThat(SarifReport.level(io.github.arjunpotluri7spec.depwatch.model.Severity.MEDIUM))
        .isEqualTo("warning");
    assertThat(SarifReport.level(io.github.arjunpotluri7spec.depwatch.model.Severity.LOW))
        .isEqualTo("note");
    assertThat(SarifReport.uri("./my app/pom.xml")).isEqualTo("my%20app/pom.xml");
    assertThat(SarifReport.uri("/tmp/x/pom.xml")).isEqualTo("file:///tmp/x/pom.xml");
    assertThat(SarifReport.uri("dir\\pom.xml")).isEqualTo("dir/pom.xml");
  }

  @Test
  void tableReportShowsSummaryAndExplanations() {
    String table = TableReport.render(RESULT);
    assertThat(table)
        .contains("SEVERITY")
        .contains("why: 2.14.1 is in [2.0-beta9, 2.15.0) from DEMO-2026-0001")
        .contains("Skipped fix versions: 2.15.0 (still affected by DEMO-2026-0002)")
        .contains(
            "Summary: 24 dependencies checked, 12 findings (2 critical, 6 high, 3 medium, 1 low), 3 suppressed");
  }

  @Test
  void markdownReportEscapesUntrustedText() {
    String md = MarkdownReport.render(RESULT);
    assertThat(md)
        .startsWith("# Depwatch report")
        .contains("## Findings")
        .contains("| critical | `com.example:logkit` |");
    assertThat(MarkdownReport.md("a|b <script>")).isEqualTo("a\\|b \\<script\\>");
    assertThat(MarkdownReport.code("x`y")).isEqualTo("`x'y`");
  }

  @Test
  void controlCharactersCannotReachTheTerminal() {
    assertThat(io.github.arjunpotluri7spec.depwatch.util.Text.clean("evil\u001b[31mred\u0007", 100))
        .doesNotContain("\u001b")
        .doesNotContain("\u0007");
  }
}
