package io.github.arjunpotluri7spec.depwatch.config;

import io.github.arjunpotluri7spec.depwatch.model.Coordinate;

/**
 * An accepted advisory. Suppressed findings stay in reports (marked suppressed) but do not count
 * toward {@code --fail-on}.
 *
 * @param coordinate limits the suppression to one package, or null for every package
 */
public record Suppression(String advisoryId, Coordinate coordinate, String reason) {

  public Suppression {
    if (reason == null || reason.isBlank()) {
      throw new IllegalArgumentException("suppression of " + advisoryId + " has no reason");
    }
  }

  public boolean matches(String id, Coordinate c) {
    return advisoryId.equals(id) && (coordinate == null || coordinate.equals(c));
  }
}
