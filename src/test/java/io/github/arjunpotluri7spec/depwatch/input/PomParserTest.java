package io.github.arjunpotluri7spec.depwatch.input;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.arjunpotluri7spec.depwatch.TestData;
import io.github.arjunpotluri7spec.depwatch.model.Dependency;
import io.github.arjunpotluri7spec.depwatch.model.Diagnostic;
import io.github.arjunpotluri7spec.depwatch.util.DepwatchException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

class PomParserTest {

  private static ParsedInput parse(String body) {
    String xml =
        "<project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n"
            + "<groupId>org.example</groupId><artifactId>app</artifactId><version>1.0</version>\n"
            + body
            + "\n</project>";
    return PomParser.parse(xml.getBytes(StandardCharsets.UTF_8), "pom.xml");
  }

  private static Map<String, String> gavs(ParsedInput in) {
    return in.dependencies().stream()
        .collect(Collectors.toMap(d -> d.coordinate().toString(), d -> d.version().original()));
  }

  @Test
  void samplePomResolvesPropertiesAndManagedVersions() throws IOException {
    byte[] data = Files.readAllBytes(TestData.SAMPLES.resolve("maven-app/pom.xml"));
    ParsedInput in = PomParser.parse(data, "pom.xml");
    assertThat(gavs(in))
        .containsEntry("com.example:logkit", "2.14.1")
        .containsEntry("com.example:jsonmapper", "2.10.1")
        .containsEntry("org.example:http-core", "4.5.13")
        .containsEntry("org.example:cachebox", "3.2.1")
        .containsEntry("com.example:widgets", "1.0-rc1")
        .containsEntry("org.example:orders-api", "3.2.0")
        .containsEntry("com.example:textutils", "1.10.0")
        .hasSize(8);
    Dependency json =
        in.dependencies().stream()
            .filter(d -> d.coordinate().artifactId().equals("jsonmapper"))
            .findFirst()
            .orElseThrow();
    assertThat(json.origin()).contains("version from dependencyManagement");
    Dependency test =
        in.dependencies().stream()
            .filter(d -> d.coordinate().artifactId().equals("textutils"))
            .findFirst()
            .orElseThrow();
    assertThat(test.dev()).isTrue();
    assertThat(test.scope()).isEqualTo("test");
    assertThat(in.diagnostics())
        .anyMatch(
            d ->
                d.message()
                    .contains("parent POM org.example:example-parent:1.4.0 is not resolved"));
  }

  @Test
  void lineNumbersPointAtArtifactId() throws IOException {
    byte[] data = Files.readAllBytes(TestData.SAMPLES.resolve("maven-app/pom.xml"));
    List<String> lines = Files.readAllLines(TestData.SAMPLES.resolve("maven-app/pom.xml"));
    for (Dependency d : PomParser.parse(data, "pom.xml").dependencies()) {
      String line = lines.get(d.location().line() - 1);
      assertThat(line).contains("<artifactId>" + d.coordinate().artifactId() + "</artifactId>");
    }
  }

  @Test
  void nestedPropertiesAndProjectBuiltIns() {
    ParsedInput in =
        parse(
            "<properties><major>3</major><minor>${major}.4</minor><full>${minor}.5</full></properties>"
                + "<dependencies>"
                + "<dependency><groupId>${project.groupId}</groupId><artifactId>a</artifactId><version>${full}</version></dependency>"
                + "<dependency><groupId>org.example</groupId><artifactId>b</artifactId><version>${project.version}</version></dependency>"
                + "</dependencies>");
    assertThat(gavs(in))
        .containsEntry("org.example:a", "3.4.5")
        .containsEntry("org.example:b", "1.0");
  }

  @Test
  void cyclicPropertiesAreReportedNotLooped() {
    ParsedInput in =
        parse(
            "<properties><a>${b}</a><b>${a}</b></properties><dependencies><dependency>"
                + "<groupId>org.example</groupId><artifactId>x</artifactId><version>${a}</version>"
                + "</dependency></dependencies>");
    assertThat(in.dependencies()).isEmpty();
    assertThat(in.unusable()).isEqualTo(1);
    assertThat(in.diagnostics()).anyMatch(d -> d.message().contains("property cycle"));
  }

  @Test
  void undefinedPropertyIsReported() {
    ParsedInput in =
        parse(
            "<dependencies><dependency><groupId>org.example</groupId><artifactId>x</artifactId>"
                + "<version>${nope.version}</version></dependency></dependencies>");
    assertThat(in.dependencies()).isEmpty();
    assertThat(in.diagnostics())
        .extracting(Diagnostic::message)
        .anyMatch(m -> m.contains("${nope.version} is not defined"));
  }

  @Test
  void missingVersionWithoutManagementIsExplained() {
    ParsedInput in =
        parse(
            "<dependencies><dependency><groupId>org.example</groupId><artifactId>x</artifactId>"
                + "</dependency></dependencies>");
    assertThat(in.dependencies()).isEmpty();
    assertThat(in.diagnostics())
        .anyMatch(d -> d.message().contains("parent POM or an imported BOM") && d.line() > 0);
  }

  @Test
  void versionRangesAreNotGuessed() {
    ParsedInput in =
        parse(
            "<dependencies><dependency><groupId>org.example</groupId><artifactId>x</artifactId>"
                + "<version>[1.0,2.0)</version></dependency></dependencies>");
    assertThat(in.dependencies()).isEmpty();
    assertThat(in.diagnostics()).anyMatch(d -> d.message().contains("uses the version range"));
  }

  @Test
  void importedBomIsReportedAndManagedOnlyEntriesAreAudited() {
    ParsedInput in =
        parse(
            "<dependencyManagement><dependencies>"
                + "<dependency><groupId>org.example</groupId><artifactId>bom</artifactId><version>1</version>"
                + "<type>pom</type><scope>import</scope></dependency>"
                + "<dependency><groupId>org.example</groupId><artifactId>pinned</artifactId><version>2.0</version></dependency>"
                + "</dependencies></dependencyManagement>");
    assertThat(gavs(in)).containsOnlyKeys("org.example:pinned");
    assertThat(in.dependencies().get(0).origin()).isEqualTo("dependencyManagement");
    assertThat(in.diagnostics())
        .anyMatch(d -> d.message().contains("BOM org.example:bom is imported"));
  }

  @Test
  void environmentPropertiesAreNeverRead() {
    ParsedInput in =
        parse(
            "<dependencies><dependency><groupId>org.example</groupId><artifactId>x</artifactId>"
                + "<version>${env.HOME}</version></dependency></dependencies>");
    assertThat(in.dependencies()).isEmpty();
    assertThat(in.diagnostics()).anyMatch(d -> d.message().contains("never read"));
  }

  @Test
  void rootMustBeProject() {
    assertThatThrownBy(
            () -> PomParser.parse("<settings/>".getBytes(StandardCharsets.UTF_8), "x.xml"))
        .isInstanceOf(DepwatchException.class)
        .hasMessageContaining("expected <project>");
  }
}
