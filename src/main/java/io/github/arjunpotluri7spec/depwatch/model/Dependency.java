package io.github.arjunpotluri7spec.depwatch.model;

import io.github.arjunpotluri7spec.depwatch.version.MavenVersion;
import java.util.Objects;
import java.util.Optional;

/**
 * One dependency read from an input file.
 *
 * @param coordinate group and artifact
 * @param version the resolved version
 * @param scope Maven scope, Gradle configurations or CycloneDX scope, for display
 * @param dev true for test-only / build-only dependencies (skipped unless {@code --include-dev})
 * @param origin where in the input it came from, such as {@code dependencies} or {@code
 *     dependencyManagement}
 * @param location file and line for reports
 * @param license an SPDX license expression, if the input carries one
 */
public record Dependency(
    Coordinate coordinate,
    MavenVersion version,
    String scope,
    boolean dev,
    String origin,
    SourceLocation location,
    String license) {

  public Dependency {
    Objects.requireNonNull(coordinate, "coordinate");
    Objects.requireNonNull(version, "version");
    Objects.requireNonNull(location, "location");
    scope = scope == null ? "" : scope;
    origin = origin == null ? "" : origin;
  }

  public Optional<String> licenseExpression() {
    return Optional.ofNullable(license);
  }

  public Dependency withLicense(String expression) {
    return new Dependency(coordinate, version, scope, dev, origin, location, expression);
  }

  /** {@code group:artifact:version}. */
  public String gav() {
    return coordinate + ":" + version;
  }
}
