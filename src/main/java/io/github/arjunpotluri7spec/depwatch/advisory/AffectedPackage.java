package io.github.arjunpotluri7spec.depwatch.advisory;

import io.github.arjunpotluri7spec.depwatch.model.Coordinate;
import io.github.arjunpotluri7spec.depwatch.version.MavenVersion;
import java.util.List;
import java.util.Optional;

/**
 * One OSV {@code affected[]} entry for a Maven package.
 *
 * @param coordinate the package
 * @param ranges {@code ECOSYSTEM} ranges
 * @param versions explicitly enumerated affected versions; matched by Maven ordering equality, so
 *     {@code 1.0} in the list also matches {@code 1.0.0}
 */
public record AffectedPackage(
    Coordinate coordinate, List<OsvRange> ranges, List<MavenVersion> versions) {

  public AffectedPackage {
    ranges = List.copyOf(ranges);
    versions = List.copyOf(versions);
  }

  /** The listed version equal to {@code v}, if any. */
  public Optional<MavenVersion> listedVersion(MavenVersion v) {
    return versions.stream().filter(v::equals).findFirst();
  }

  public boolean affects(MavenVersion v) {
    return listedVersion(v).isPresent() || ranges.stream().anyMatch(r -> r.affects(v));
  }
}
