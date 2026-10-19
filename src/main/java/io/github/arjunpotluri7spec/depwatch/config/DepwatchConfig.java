package io.github.arjunpotluri7spec.depwatch.config;

import io.github.arjunpotluri7spec.depwatch.license.LicensePolicy;
import java.util.List;
import java.util.Optional;

/**
 * The validated configuration file.
 *
 * @param licensePolicy empty when the file has no {@code licenses} section
 */
public record DepwatchConfig(
    Optional<LicensePolicy> licensePolicy, List<Suppression> suppressions) {

  public DepwatchConfig {
    suppressions = List.copyOf(suppressions);
  }

  public static DepwatchConfig empty() {
    return new DepwatchConfig(Optional.empty(), List.of());
  }
}
