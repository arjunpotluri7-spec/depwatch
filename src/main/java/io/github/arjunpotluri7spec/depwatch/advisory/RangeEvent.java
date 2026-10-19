package io.github.arjunpotluri7spec.depwatch.advisory;

import io.github.arjunpotluri7spec.depwatch.version.MavenVersion;
import java.util.Locale;
import java.util.Objects;

/**
 * One OSV range event. For {@code introduced: "0"} the version is null, meaning "from the very
 * first version".
 */
public record RangeEvent(Kind kind, String raw, MavenVersion version) {

  /** OSV event types, in the order used to break ties between events at the same version. */
  public enum Kind {
    INTRODUCED("introduced"),
    FIXED("fixed"),
    LAST_AFFECTED("last_affected"),
    LIMIT("limit");

    private final String key;

    Kind(String key) {
      this.key = key;
    }

    /** The JSON key, such as {@code last_affected}. */
    public String key() {
      return key;
    }

    public static Kind fromKey(String key) {
      for (Kind k : values()) {
        if (k.key.equals(key)) {
          return k;
        }
      }
      throw new IllegalArgumentException(
          "unknown range event '" + key.toLowerCase(Locale.ROOT) + "'");
    }
  }

  public RangeEvent {
    Objects.requireNonNull(kind, "kind");
    Objects.requireNonNull(raw, "raw");
    if (version == null && !(kind == Kind.INTRODUCED && raw.equals("0"))) {
      throw new IllegalArgumentException("only 'introduced: 0' may omit a version");
    }
  }

  /** Creates an event, treating {@code introduced: "0"} as "since the beginning". */
  public static RangeEvent of(Kind kind, String raw) {
    if (kind == Kind.INTRODUCED && "0".equals(raw)) {
      return new RangeEvent(kind, raw, null);
    }
    return new RangeEvent(kind, raw, MavenVersion.parse(raw));
  }

  public boolean isIntroducedZero() {
    return version == null;
  }

  @Override
  public String toString() {
    return kind.key() + " " + raw;
  }
}
