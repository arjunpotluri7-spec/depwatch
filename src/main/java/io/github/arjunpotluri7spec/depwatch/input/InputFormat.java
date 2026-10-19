package io.github.arjunpotluri7spec.depwatch.input;

import java.util.Locale;
import java.util.Optional;

/** Supported input formats. */
public enum InputFormat {
  MAVEN_POM("pom"),
  GRADLE_LOCKFILE("gradle-lockfile"),
  CYCLONEDX_JSON("cyclonedx");

  private final String id;

  InputFormat(String id) {
    this.id = id;
  }

  /** The name used on the command line and in reports. */
  public String id() {
    return id;
  }

  public static Optional<InputFormat> fromId(String text) {
    if (text == null) {
      return Optional.empty();
    }
    String t = text.trim().toLowerCase(Locale.ROOT);
    for (InputFormat f : values()) {
      if (f.id.equals(t)) {
        return Optional.of(f);
      }
    }
    return Optional.empty();
  }
}
