package io.github.arjunpotluri7spec.depwatch.scan;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.arjunpotluri7spec.depwatch.TestData;
import io.github.arjunpotluri7spec.depwatch.model.Severity;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Locks down the result of scanning the shipped samples. If this changes, the README's sample
 * output needs regenerating too.
 */
class SampleRegressionTest {

  private static String row(Finding f) {
    String fix = f.fix() == null ? "" : f.fix().shortText();
    return String.join(
        " | ",
        f.severity().label(),
        f.dependency().gav(),
        f.ruleId(),
        fix,
        f.dependency().location().toString(),
        f.suppressed() ? "suppressed" : "active");
  }

  @Test
  void allSamplesWithConfigAndDevDependencies() {
    ScanResult r = ScanFixtures.allSamples();
    List<String> rows = r.findings().stream().map(SampleRegressionTest::row).toList();
    assertThat(rows)
        .containsExactly(
            "critical | com.example:logkit:2.14.1 | DEMO-2026-0001 | 2.16.0 | samples/maven-app/pom.xml:46 | active",
            "critical | com.example:logkit:2.14.1 | DEMO-2026-0001 | 2.16.0 | samples/sbom/app.cdx.json:21 | active",
            "high | com.example:jsonmapper:2.10.1 | DEMO-2026-0003 | 2.10.5.1 | samples/maven-app/pom.xml:51 | active",
            "high | com.example:jsonmapper:2.11.0 | DEMO-2026-0003 | 2.11.4 | samples/gradle-app/gradle.lockfile:5 | active",
            "high | org.example:cachebox:3.1.5 | DEMO-2026-0008 | 3.2.1 | samples/gradle-app/gradle.lockfile:8 | active",
            "high | org.example:http-core:4.5.13 | DEMO-2026-0005 | 5.1.2 (major) | samples/maven-app/pom.xml:55 | active",
            "high | org.example:http-core:4.5.13 | DEMO-2026-0005 | 5.1.2 (major) | samples/sbom/app.cdx.json:76 | active",
            "high | org.example:gpl-widget:1.0.0 | license-denied |  | samples/sbom/app.cdx.json:37 | active",
            "medium | com.example:textutils:1.9 | DEMO-2026-0006 | none known | samples/gradle-app/gradle.lockfile:7 | suppressed",
            "medium | com.example:textutils:1.10.0 | DEMO-2026-0006 | none known | samples/maven-app/pom.xml:79 | suppressed",
            "medium | com.example:textutils:1.10.1 | DEMO-2026-0006 | none known | samples/sbom/app.cdx.json:95 | suppressed",
            "medium | com.example:widgets:1.0-rc1 | DEMO-2026-0009 | 1.0 | samples/maven-app/pom.xml:64 | active",
            "medium | org.example:yamlite:1.30 | DEMO-2026-0004 | none known | samples/maven-app/pom.xml:69 | active",
            "medium | org.example:mystery-lib:0.3 | license-unknown |  | samples/sbom/app.cdx.json:69 | active",
            "low | org.example:weak-copyleft:2.1 | license-review |  | samples/sbom/app.cdx.json:53 | active");
    assertThat(r.activeFindings()).isEqualTo(12);
    assertThat(r.failsAt(Severity.CRITICAL)).isTrue();
    assertThat(r.licenseChecks()).isTrue();
    assertThat(r.failedInputs()).isZero();
  }

  @Test
  void devDependenciesAreSkippedByDefault() {
    ScanResult r = ScanFixtures.scan(false, false, TestData.SAMPLES.resolve("maven-app/pom.xml"));
    assertThat(r.findings())
        .noneMatch(f -> f.dependency().coordinate().artifactId().equals("textutils"));
    assertThat(r.inputs().get(0).devSkipped()).isEqualTo(1);
    assertThat(r.inputs().get(0).checked()).isEqualTo(7);
    assertThat(r.licenseChecks()).isFalse();
  }

  @Test
  void safeLockfileVersionsProduceNoFindings() {
    ScanResult r =
        ScanFixtures.scan(false, false, TestData.SAMPLES.resolve("gradle-app/gradle.lockfile"));
    assertThat(r.findings())
        .extracting(f -> f.dependency().coordinate().artifactId())
        .containsExactlyInAnyOrder("jsonmapper", "cachebox");
  }
}
