package io.github.arjunpotluri7spec.depwatch.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.arjunpotluri7spec.depwatch.TestData;
import io.github.arjunpotluri7spec.depwatch.license.LicenseVerdict;
import io.github.arjunpotluri7spec.depwatch.model.Coordinate;
import io.github.arjunpotluri7spec.depwatch.model.Dependency;
import io.github.arjunpotluri7spec.depwatch.model.SourceLocation;
import io.github.arjunpotluri7spec.depwatch.util.DepwatchException;
import io.github.arjunpotluri7spec.depwatch.util.Limits;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

class ConfigLoaderTest {

  @Test
  void exampleConfigLoads() {
    DepwatchConfig c = ConfigLoader.load(Path.of("config.example.yaml"), Limits.defaults());
    assertThat(c.licensePolicy()).isPresent();
    assertThat(c.licensePolicy().get().exceptions()).hasSize(1);
    assertThat(c.suppressions())
        .singleElement()
        .satisfies(
            s -> {
              assertThat(s.advisoryId()).isEqualTo("DEMO-2026-0006");
              assertThat(s.matches("DEMO-2026-0006", Coordinate.parse("com.example:textutils")))
                  .isTrue();
              assertThat(s.matches("DEMO-2026-0006", Coordinate.parse("com.example:other")))
                  .isFalse();
            });
    assertThat(
            c.licensePolicy()
                .get()
                .evaluate(Coordinate.parse("org.example:legacy-parser"), "GPL-2.0-only")
                .status())
        .isEqualTo(LicenseVerdict.Status.ALLOWED);
  }

  @Test
  void exceptionWithoutReasonIsRejected() {
    String yaml =
        "licenses: {allowed: [MIT]}\nexceptions:\n  - package: org.example:x\n    license: GPL-2.0-only\n";
    assertThatThrownBy(() -> ConfigLoader.parse(yaml, "c.yaml"))
        .isInstanceOf(DepwatchException.class)
        .hasMessage(
            "c.yaml: exceptions[0].reason is required: every license exception must say why it exists");
  }

  @Test
  void blankReasonIsRejectedToo() {
    String yaml =
        "licenses: {allowed: [MIT]}\nexceptions:\n  - {package: 'org.example:x', reason: '  '}\n";
    assertThatThrownBy(() -> ConfigLoader.parse(yaml, "c.yaml"))
        .hasMessageContaining("reason is required");
  }

  @Test
  void suppressionWithoutReasonIsRejected() {
    assertThatThrownBy(() -> ConfigLoader.parse("suppressions:\n  - advisory: DEMO-1\n", "c.yaml"))
        .hasMessageContaining("suppressions[0].reason is required");
  }

  @Test
  void unknownKeysAreErrors() {
    assertThatThrownBy(() -> ConfigLoader.parse("licences: {}\n", "c.yaml"))
        .hasMessageContaining("unknown key 'licences'");
    assertThatThrownBy(() -> ConfigLoader.parse("licenses: {allow: [MIT]}\n", "c.yaml"))
        .hasMessageContaining("licenses: unknown key 'allow'");
  }

  @Test
  void typeErrorsNameTheKey() {
    assertThatThrownBy(() -> ConfigLoader.parse("licenses: {allowed: MIT}\n", "c.yaml"))
        .hasMessageContaining("licenses.allowed must be a list");
    assertThatThrownBy(() -> ConfigLoader.parse("licenses: {allowed: [MIT, 'A B']}\n", "c.yaml"))
        .hasMessageContaining("SPDX identifiers");
    assertThatThrownBy(() -> ConfigLoader.parse("- just\n- a list\n", "c.yaml"))
        .hasMessageContaining("top level must be a mapping");
  }

  @Test
  void safeConstructorRefusesJavaObjects() {
    String yaml = "licenses: !!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[]]]\n";
    assertThatThrownBy(() -> ConfigLoader.parse(yaml, "evil.yaml"))
        .isInstanceOf(DepwatchException.class)
        .hasMessageContaining("evil.yaml")
        .hasMessageContaining("invalid YAML");
  }

  @Test
  void duplicateKeysAndAliasBombsAreRejected() {
    assertThatThrownBy(() -> ConfigLoader.parse("licenses: {}\nlicenses: {}\n", "c.yaml"))
        .hasMessageContaining("invalid YAML");
    StringBuilder bomb = new StringBuilder("a: &a [x, x]\n");
    for (char c = 'b'; c <= 'm'; c++) {
      char p = (char) (c - 1);
      bomb.append(c)
          .append(": &")
          .append(c)
          .append(" [*")
          .append(p)
          .append(", *")
          .append(p)
          .append("]\n");
    }
    assertThatThrownBy(() -> ConfigLoader.parse(bomb.toString(), "bomb.yaml"))
        .hasMessageContaining("invalid YAML");
  }

  @Test
  void emptyFileIsAnEmptyConfig() {
    assertThat(ConfigLoader.parse("", "c.yaml").licensePolicy()).isEmpty();
  }

  @Test
  void licenseMapLoadsAndPrefersVersionSpecificKeys() {
    LicenseMap map =
        ConfigLoader.loadLicenseMap(
            TestData.SAMPLES.resolve("licenses.example.yaml"), Limits.defaults());
    Dependency d =
        new Dependency(
            Coordinate.parse("com.example:logkit"),
            TestData.v("2.14.1"),
            "compile",
            false,
            "dependencies",
            SourceLocation.of("pom.xml", 1),
            null);
    assertThat(map.lookup(d)).contains("Apache-2.0");
    LicenseMap specific =
        new LicenseMap(
            java.util.Map.of("com.example:logkit", "MIT", "com.example:logkit:2.14.1", "ISC"));
    assertThat(specific.lookup(d)).contains("ISC");
  }
}
