package io.github.arjunpotluri7spec.depwatch.input;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.arjunpotluri7spec.depwatch.TestData;
import io.github.arjunpotluri7spec.depwatch.model.Dependency;
import io.github.arjunpotluri7spec.depwatch.util.DepwatchException;
import io.github.arjunpotluri7spec.depwatch.util.Json;
import java.io.IOException;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

class CycloneDxParserTest {

  private static ParsedInput sample() throws IOException {
    return CycloneDxParser.parse(
        Files.readString(TestData.SAMPLES.resolve("sbom/app.cdx.json")), "app.cdx.json");
  }

  @Test
  void readsMavenComponentsIncludingNestedOnes() throws IOException {
    ParsedInput in = sample();
    assertThat(in.hasLicenseData()).isTrue();
    assertThat(in.dependencies())
        .extracting(Dependency::gav)
        .contains("com.example:logkit:2.14.1", "org.example:http-codec:1.15")
        .doesNotContain("org.example:billing-portal:1.0.0")
        .hasSize(10);
    assertThat(in.diagnostics()).anyMatch(d -> d.message().contains("pkg:npm/example-merge"));
  }

  @Test
  void licensesAndScopes() throws IOException {
    Map<String, Dependency> byName =
        sample().dependencies().stream()
            .collect(Collectors.toMap(d -> d.coordinate().artifactId(), d -> d));
    assertThat(byName.get("logkit").license()).isEqualTo("Apache-2.0");
    assertThat(byName.get("dual-licensed").license()).isEqualTo("MIT OR GPL-3.0-only");
    assertThat(byName.get("mystery-lib").license()).isNull();
    assertThat(byName.get("textutils").dev()).isTrue();
    assertThat(byName.get("logkit").dev()).isFalse();
  }

  @Test
  void lineNumbersPointAtThePurl() throws IOException {
    List<String> lines = Files.readAllLines(TestData.SAMPLES.resolve("sbom/app.cdx.json"));
    for (Dependency d : sample().dependencies()) {
      assertThat(lines.get(d.location().line() - 1))
          .contains("\"purl\"")
          .contains(d.coordinate().artifactId());
    }
  }

  @Test
  void severalLicenseEntriesAreCombinedWithAnd() {
    var node =
        Json.parse(
            "{\"licenses\": [{\"license\": {\"id\": \"MIT\"}}, {\"license\": {\"name\": \"Acme"
                + " Commercial\"}}, {\"expression\": \"A OR B\"}]}",
            "x");
    assertThat(CycloneDxParser.licenses(node))
        .isEqualTo("MIT AND LicenseRef-Acme-Commercial AND (A OR B)");
  }

  @Test
  void notCycloneDxIsRejected() {
    assertThatThrownBy(() -> CycloneDxParser.parse("{\"components\": []}", "x.json"))
        .isInstanceOf(DepwatchException.class)
        .hasMessageContaining("not a CycloneDX JSON document");
    assertThatThrownBy(() -> CycloneDxParser.parse("{\"bomFormat\": \"CycloneDX\",", "y.json"))
        .isInstanceOf(DepwatchException.class)
        .hasMessageContaining("invalid JSON");
  }

  @Test
  void componentsWithoutPurlOrWithBadVersionAreCounted() {
    String json =
        "{\"bomFormat\": \"CycloneDX\", \"components\": ["
            + "{\"name\": \"nopurl\"},"
            + "{\"name\": \"bad\", \"purl\": \"pkg:maven/org.example/bad@1%200\"},"
            + "{\"name\": \"ok\", \"purl\": \"pkg:maven/org.example/ok@1.0\"}]}";
    ParsedInput in = CycloneDxParser.parse(json, "s.json");
    assertThat(in.dependencies()).extracting(Dependency::gav).containsExactly("org.example:ok:1.0");
    assertThat(in.unusable()).isEqualTo(2);
  }
}
