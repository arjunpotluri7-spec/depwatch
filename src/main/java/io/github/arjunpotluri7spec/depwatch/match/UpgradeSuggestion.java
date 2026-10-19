package io.github.arjunpotluri7spec.depwatch.match;

import io.github.arjunpotluri7spec.depwatch.version.MavenVersion;
import java.util.Optional;

/**
 * The smallest safe upgrade for a dependency.
 *
 * @param version the suggested version; empty for {@link Kind#NOT_NEEDED} and {@link
 *     Kind#NONE_KNOWN}
 * @param explanation one or more sentences saying how the version was chosen
 */
public record UpgradeSuggestion(Kind kind, MavenVersion version, String explanation) {

  public enum Kind {
    /** The current version is not affected by any known advisory. */
    NOT_NEEDED,
    /** A safe version exists within the current major version. */
    SAME_MAJOR,
    /** The lowest safe version is in a later major version. */
    NEXT_MAJOR,
    /** The database records no version that is known to be safe. */
    NONE_KNOWN
  }

  public Optional<MavenVersion> target() {
    return Optional.ofNullable(version);
  }

  /** Short form for tables: {@code 2.16.0}, {@code 5.1.2 (major)}, {@code none known}. */
  public String shortText() {
    return switch (kind) {
      case NOT_NEEDED -> "-";
      case SAME_MAJOR -> version.toString();
      case NEXT_MAJOR -> version + " (major)";
      case NONE_KNOWN -> "none known";
    };
  }
}
