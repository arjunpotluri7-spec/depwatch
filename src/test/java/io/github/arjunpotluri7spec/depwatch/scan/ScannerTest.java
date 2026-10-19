package io.github.arjunpotluri7spec.depwatch.scan;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.arjunpotluri7spec.depwatch.TestData;
import io.github.arjunpotluri7spec.depwatch.advisory.OsvLoader;
import io.github.arjunpotluri7spec.depwatch.config.ConfigLoader;
import io.github.arjunpotluri7spec.depwatch.config.DepwatchConfig;
import io.github.arjunpotluri7spec.depwatch.config.LicenseMap;
import io.github.arjunpotluri7spec.depwatch.model.Diagnostic;
import io.github.arjunpotluri7spec.depwatch.util.Limits;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class ScannerTest {

  private static ScanResult run(List<Path> inputs, DepwatchConfig cfg, LicenseMap map) {
    return Scanner.scan(
        new Scanner.Request(
            inputs,
            Optional.empty(),
            OsvLoader.load(TestData.SAMPLE_DB, Limits.defaults()),
            cfg,
            map,
            false,
            Limits.defaults(),
            "test"));
  }

  @Test
  void rejectedInputIsReportedAndOthersStillScan() {
    ScanResult r =
        run(
            List.of(
                Path.of("src/test/resources/xxe/malicious-external-entity-pom.xml"),
                TestData.SAMPLES.resolve("maven-app/pom.xml")),
            DepwatchConfig.empty(),
            null);
    assertThat(r.failedInputs()).isEqualTo(1);
    assertThat(r.inputs().get(0).error()).contains("XXE protection");
    assertThat(r.diagnostics()).anyMatch(d -> d.level() == Diagnostic.Level.ERROR);
    assertThat(r.activeFindings()).isEqualTo(5);
  }

  @Test
  void licenseMapEnablesLicenseChecksForPoms() {
    DepwatchConfig cfg = ConfigLoader.load(Path.of("config.example.yaml"), Limits.defaults());
    LicenseMap map = new LicenseMap(Map.of("com.example:logkit", "GPL-3.0-only"));
    ScanResult r = run(List.of(TestData.SAMPLES.resolve("maven-app/pom.xml")), cfg, map);
    assertThat(r.licenseChecks()).isTrue();
    assertThat(r.findings())
        .anyMatch(
            f ->
                f.ruleId().equals(Finding.LICENSE_DENIED)
                    && f.dependency().coordinate().artifactId().equals("logkit"))
        .anyMatch(
            f ->
                f.ruleId().equals(Finding.LICENSE_UNKNOWN)
                    && f.dependency().coordinate().artifactId().equals("widgets"));
  }

  @Test
  void policyWithoutLicenseDataIsReportedNotApplied() {
    DepwatchConfig cfg = ConfigLoader.load(Path.of("config.example.yaml"), Limits.defaults());
    ScanResult r = run(List.of(TestData.SAMPLES.resolve("maven-app/pom.xml")), cfg, null);
    assertThat(r.licenseChecks()).isFalse();
    assertThat(r.findings()).noneMatch(f -> f.type() == Finding.Type.LICENSE);
    assertThat(r.diagnostics()).anyMatch(d -> d.message().contains("license policy not applied"));
  }
}
