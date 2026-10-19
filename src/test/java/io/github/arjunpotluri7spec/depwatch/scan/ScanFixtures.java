package io.github.arjunpotluri7spec.depwatch.scan;

import io.github.arjunpotluri7spec.depwatch.TestData;
import io.github.arjunpotluri7spec.depwatch.advisory.OsvLoader;
import io.github.arjunpotluri7spec.depwatch.config.ConfigLoader;
import io.github.arjunpotluri7spec.depwatch.config.DepwatchConfig;
import io.github.arjunpotluri7spec.depwatch.util.Limits;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

/** Runs scans over the shipped samples. */
public final class ScanFixtures {

  private ScanFixtures() {}

  public static ScanResult scan(boolean withConfig, boolean includeDev, Path... inputs) {
    DepwatchConfig cfg =
        withConfig
            ? ConfigLoader.load(Path.of("config.example.yaml"), Limits.defaults())
            : DepwatchConfig.empty();
    return Scanner.scan(
        new Scanner.Request(
            List.of(inputs),
            Optional.empty(),
            OsvLoader.load(TestData.SAMPLE_DB, Limits.defaults()),
            cfg,
            null,
            includeDev,
            Limits.defaults(),
            "test"));
  }

  public static ScanResult allSamples() {
    return scan(
        true,
        true,
        TestData.SAMPLES.resolve("maven-app/pom.xml"),
        TestData.SAMPLES.resolve("gradle-app/gradle.lockfile"),
        TestData.SAMPLES.resolve("sbom/app.cdx.json"));
  }
}
