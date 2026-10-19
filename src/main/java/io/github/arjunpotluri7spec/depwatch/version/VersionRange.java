package io.github.arjunpotluri7spec.depwatch.version;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * A Maven version requirement: either a soft requirement ({@code 1.0}, a recommendation that any
 * version satisfies) or one or more restrictions such as {@code [1.2,2.0)}, {@code (,1.5]}, {@code
 * [1.0]} or the union {@code [1,2),[3,4)}.
 *
 * <p>Parsing follows Maven's {@code VersionRange.createFromVersionSpec}: sets are listed in
 * ascending order and may not overlap, a single version must be written {@code [v]}, and a lower
 * bound may not exceed the upper bound. Depwatch is stricter in two places: a restriction may
 * contain at most one comma, and anything left over after the last set is an error.
 */
public final class VersionRange {

  /** One interval. A null bound is unbounded on that side. */
  public record Restriction(
      MavenVersion lower, boolean lowerInclusive, MavenVersion upper, boolean upperInclusive) {

    public boolean contains(MavenVersion v) {
      if (lower != null) {
        int c = lower.compareTo(v);
        if (c > 0 || (c == 0 && !lowerInclusive)) {
          return false;
        }
      }
      if (upper != null) {
        int c = upper.compareTo(v);
        if (c < 0 || (c == 0 && !upperInclusive)) {
          return false;
        }
      }
      return true;
    }

    @Override
    public String toString() {
      if (lower != null && lower.equals(upper) && lowerInclusive && upperInclusive) {
        return "[" + lower + "]";
      }
      return (lowerInclusive ? "[" : "(")
          + (lower == null ? "" : lower.toString())
          + ","
          + (upper == null ? "" : upper.toString())
          + (upperInclusive ? "]" : ")");
    }
  }

  /** Longest range specification accepted. */
  public static final int MAX_SPEC_LENGTH = 2048;

  private final String spec;
  private final MavenVersion recommended;
  private final List<Restriction> restrictions;

  private VersionRange(String spec, MavenVersion recommended, List<Restriction> restrictions) {
    this.spec = spec;
    this.recommended = recommended;
    this.restrictions = List.copyOf(restrictions);
  }

  /**
   * Parses a Maven version specification.
   *
   * @throws InvalidVersionException with a message naming the problem
   */
  public static VersionRange parse(String spec) {
    if (spec == null || spec.isBlank()) {
      throw new InvalidVersionException("version range is empty");
    }
    if (spec.length() > MAX_SPEC_LENGTH) {
      throw new InvalidVersionException(
          "version range is longer than " + MAX_SPEC_LENGTH + " characters");
    }
    String rest = spec.trim();
    if (!rest.startsWith("[") && !rest.startsWith("(")) {
      if (rest.indexOf(']') >= 0 || rest.indexOf(')') >= 0) {
        throw new InvalidVersionException("range '" + spec + "' must start with '[' or '('");
      }
      return new VersionRange(spec, MavenVersion.parse(rest), List.of());
    }
    List<Restriction> out = new ArrayList<>();
    MavenVersion previousUpper = null;
    while (rest.startsWith("[") || rest.startsWith("(")) {
      int close = firstClose(rest);
      if (close < 0) {
        throw new InvalidVersionException("range '" + spec + "' has an unclosed set");
      }
      Restriction r = parseRestriction(rest.substring(0, close + 1), spec);
      if (!out.isEmpty()) {
        if (previousUpper == null) {
          throw new InvalidVersionException(
              "range '" + spec + "' continues after a set with no upper bound");
        }
        if (r.lower() == null || r.lower().compareTo(previousUpper) < 0) {
          throw new InvalidVersionException(
              "range '" + spec + "' has overlapping or out-of-order sets");
        }
      }
      out.add(r);
      previousUpper = r.upper();
      rest = rest.substring(close + 1).trim();
      if (rest.startsWith(",")) {
        rest = rest.substring(1).trim();
        if (rest.isEmpty()) {
          throw new InvalidVersionException("range '" + spec + "' ends with a comma");
        }
      }
    }
    if (!rest.isEmpty()) {
      throw new InvalidVersionException(
          "range '" + spec + "' has unexpected text after the last set: '" + rest + "'");
    }
    return new VersionRange(spec, null, out);
  }

  private static int firstClose(String s) {
    int bracket = s.indexOf(']');
    int paren = s.indexOf(')');
    if (bracket < 0) {
      return paren;
    }
    if (paren < 0) {
      return bracket;
    }
    return Math.min(bracket, paren);
  }

  private static Restriction parseRestriction(String set, String spec) {
    boolean lowerInclusive = set.startsWith("[");
    boolean upperInclusive = set.endsWith("]");
    String body = set.substring(1, set.length() - 1).trim();
    int comma = body.indexOf(',');
    if (comma < 0) {
      if (!lowerInclusive || !upperInclusive) {
        throw new InvalidVersionException(
            "range '" + spec + "': a single version must be written as [" + body + "]");
      }
      if (body.isEmpty()) {
        throw new InvalidVersionException("range '" + spec + "' has an empty set");
      }
      MavenVersion v = parseBound(body, spec);
      return new Restriction(v, true, v, true);
    }
    if (body.indexOf(',', comma + 1) >= 0) {
      throw new InvalidVersionException(
          "range '" + spec + "': set '" + set + "' has more than one comma");
    }
    String lowerText = body.substring(0, comma).trim();
    String upperText = body.substring(comma + 1).trim();
    MavenVersion lower = lowerText.isEmpty() ? null : parseBound(lowerText, spec);
    MavenVersion upper = upperText.isEmpty() ? null : parseBound(upperText, spec);
    if (lower != null && upper != null) {
      int c = upper.compareTo(lower);
      if (c < 0 || (c == 0 && (!lowerInclusive || !upperInclusive))) {
        throw new InvalidVersionException(
            "range '" + spec + "': set '" + set + "' is empty (lower bound is above upper bound)");
      }
    }
    return new Restriction(lower, lowerInclusive, upper, upperInclusive);
  }

  private static MavenVersion parseBound(String text, String spec) {
    try {
      return MavenVersion.parse(text);
    } catch (InvalidVersionException e) {
      throw new InvalidVersionException("range '" + spec + "': " + e.getMessage());
    }
  }

  /** The specification string as given. */
  public String spec() {
    return spec;
  }

  /** True for a plain version such as {@code 1.0}: Maven treats it as a recommendation only. */
  public boolean isSoftRequirement() {
    return recommended != null;
  }

  public Optional<MavenVersion> recommendedVersion() {
    return Optional.ofNullable(recommended);
  }

  public List<Restriction> restrictions() {
    return restrictions;
  }

  /**
   * True if the version satisfies this requirement. A soft requirement is satisfied by every
   * version, as in Maven.
   */
  public boolean contains(MavenVersion v) {
    return isSoftRequirement() || matchingRestriction(v).isPresent();
  }

  /** The first restriction containing the version. Always empty for a soft requirement. */
  public Optional<Restriction> matchingRestriction(MavenVersion v) {
    for (Restriction r : restrictions) {
      if (r.contains(v)) {
        return Optional.of(r);
      }
    }
    return Optional.empty();
  }

  @Override
  public String toString() {
    if (recommended != null) {
      return recommended.toString();
    }
    StringBuilder b = new StringBuilder();
    for (Restriction r : restrictions) {
      if (b.length() > 0) {
        b.append(',');
      }
      b.append(r);
    }
    return b.toString();
  }
}
