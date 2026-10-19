package io.github.arjunpotluri7spec.depwatch.license;

import io.github.arjunpotluri7spec.depwatch.model.Coordinate;
import java.util.Objects;

/**
 * A per-package exception to the license policy. Every exception must say why it exists.
 *
 * @param license the single license id it permits, or null to accept the package's licenses
 *     whatever they are
 */
public record LicenseException(Coordinate coordinate, String license, String reason) {

  public LicenseException {
    Objects.requireNonNull(coordinate, "coordinate");
    if (reason == null || reason.isBlank()) {
      throw new IllegalArgumentException(
          "license exception for " + coordinate + " has no reason; every exception needs one");
    }
  }
}
