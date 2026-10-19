package io.github.arjunpotluri7spec.depwatch.model;

import java.util.Comparator;

/** A Maven {@code groupId:artifactId} pair. Matching is exact and case-sensitive, as in Maven. */
public record Coordinate(String groupId, String artifactId) implements Comparable<Coordinate> {

  private static final int MAX_PART = 256;
  private static final Comparator<Coordinate> ORDER =
      Comparator.comparing(Coordinate::groupId).thenComparing(Coordinate::artifactId);

  public Coordinate {
    groupId = checkPart(groupId, "groupId");
    artifactId = checkPart(artifactId, "artifactId");
  }

  /**
   * Parses {@code group:artifact}.
   *
   * @throws IllegalArgumentException with a user-facing message
   */
  public static Coordinate parse(String text) {
    if (text == null) {
      throw new IllegalArgumentException("package name is missing");
    }
    String[] parts = text.split(":", -1);
    if (parts.length != 2) {
      throw new IllegalArgumentException(
          "package name '" + text + "' is not in group:artifact form");
    }
    return new Coordinate(parts[0], parts[1]);
  }

  private static String checkPart(String value, String what) {
    if (value == null || value.isEmpty()) {
      throw new IllegalArgumentException(what + " is empty");
    }
    if (value.length() > MAX_PART) {
      throw new IllegalArgumentException(what + " is longer than " + MAX_PART + " characters");
    }
    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      if (c == ':' || c == '/' || Character.isWhitespace(c) || Character.isISOControl(c)) {
        throw new IllegalArgumentException(what + " '" + value + "' contains an invalid character");
      }
    }
    return value;
  }

  @Override
  public int compareTo(Coordinate o) {
    return ORDER.compare(this, o);
  }

  @Override
  public String toString() {
    return groupId + ":" + artifactId;
  }
}
