package io.github.arjunpotluri7spec.depwatch.version;

import java.math.BigInteger;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * A Maven version with the ordering of Maven's {@code ComparableVersion}.
 *
 * <p>The rules follow the "Version Order Specification" in the Maven POM reference
 * (https://maven.apache.org/pom.html#version-order-specification):
 *
 * <ul>
 *   <li>The string is split into tokens at {@code .}, {@code -} and at transitions between digits
 *       and letters. A transition counts as a hyphen. Empty tokens become {@code 0}.
 *   <li>Trailing "null" tokens ({@code 0}, {@code ""}, {@code final}, {@code ga}, {@code release})
 *       are trimmed, at the end and before each hyphen.
 *   <li>Qualifiers order as {@code alpha < beta < milestone < rc = cr < snapshot < "" = final = ga
 *       = release < sp}, then any other qualifier alphabetically. {@code a}, {@code b} and {@code
 *       m} followed directly by a digit mean alpha, beta and milestone.
 *   <li>Between token kinds: {@code .qualifier = -qualifier < -number < .number}.
 * </ul>
 *
 * <p>Depwatch is stricter than Maven about what it accepts as a version string: it rejects empty
 * strings, strings longer than {@link #MAX_LENGTH}, whitespace, control characters and the range
 * syntax characters {@code [ ] ( ) ,}, so a version can never be confused with a range.
 */
public final class MavenVersion implements Comparable<MavenVersion> {

  /** Longest version string accepted. Real versions are far shorter. */
  public static final int MAX_LENGTH = 256;

  private final String original;
  private final ListItem items;

  private MavenVersion(String original, ListItem items) {
    this.original = original;
    this.items = items;
  }

  /**
   * Parses a version string.
   *
   * @throws InvalidVersionException if the string is not an acceptable version
   */
  public static MavenVersion parse(String text) {
    if (text == null) {
      throw new InvalidVersionException("version is missing");
    }
    if (text.isEmpty()) {
      throw new InvalidVersionException("version is empty");
    }
    if (text.length() > MAX_LENGTH) {
      throw new InvalidVersionException(
          "version is longer than " + MAX_LENGTH + " characters (" + text.length() + ")");
    }
    for (int i = 0; i < text.length(); i++) {
      char c = text.charAt(i);
      if (Character.isWhitespace(c) || Character.isISOControl(c)) {
        throw new InvalidVersionException(
            "version '" + printable(text) + "' contains whitespace or a control character");
      }
      if ("[](),".indexOf(c) >= 0) {
        throw new InvalidVersionException(
            "version '" + text + "' contains '" + c + "', which is only valid in a range");
      }
    }
    return new MavenVersion(text, tokenize(text));
  }

  /** Like {@link #parse} but returns empty instead of throwing. */
  public static Optional<MavenVersion> tryParse(String text) {
    try {
      return Optional.of(parse(text));
    } catch (InvalidVersionException e) {
      return Optional.empty();
    }
  }

  /** The string this version was parsed from, unchanged. */
  public String original() {
    return original;
  }

  /**
   * The normalized form, using Maven's notation: items separated by {@code .}, sublists (which
   * start at a hyphen or a digit/letter transition) introduced by {@code -}. Two versions are equal
   * exactly when their canonical forms are equal.
   */
  public String canonical() {
    return items.toString();
  }

  /** The leading numeric component, if the version starts with a number. */
  public Optional<BigInteger> major() {
    if (!items.isEmpty() && items.get(0) instanceof NumberItem n) {
      return Optional.of(n.value);
    }
    if (items.isEmpty()) {
      return Optional.of(BigInteger.ZERO);
    }
    return Optional.empty();
  }

  /**
   * True when any qualifier sorts below a release ({@code alpha}, {@code beta}, {@code milestone},
   * {@code rc}/{@code cr}, {@code snapshot}).
   */
  public boolean isPreRelease() {
    return items.containsPreReleaseQualifier();
  }

  @Override
  public int compareTo(MavenVersion other) {
    return Integer.signum(items.compareTo(other.items));
  }

  public boolean isBefore(MavenVersion other) {
    return compareTo(other) < 0;
  }

  public boolean isAfter(MavenVersion other) {
    return compareTo(other) > 0;
  }

  /**
   * Equality is by Maven ordering identity: {@code 1.0}, {@code 1.0.0} and {@code 1-0} are equal.
   */
  @Override
  public boolean equals(Object o) {
    return o instanceof MavenVersion other && items.equals(other.items);
  }

  @Override
  public int hashCode() {
    return items.hashCode();
  }

  @Override
  public String toString() {
    return original;
  }

  private static String printable(String s) {
    StringBuilder b = new StringBuilder();
    for (int i = 0; i < s.length() && b.length() < 64; i++) {
      char c = s.charAt(i);
      b.append(Character.isISOControl(c) ? '?' : c);
    }
    return b.toString();
  }

  // ---------------------------------------------------------------------------------------------
  // Tokenizer

  private static ListItem tokenize(String text) {
    String v = text.toLowerCase(Locale.ROOT);
    ListItem root = new ListItem();
    ListItem list = root;
    Deque<ListItem> opened = new ArrayDeque<>();
    opened.push(root);
    boolean inDigits = false;
    int start = 0;
    for (int i = 0; i < v.length(); i++) {
      char c = v.charAt(i);
      if (c == '.' || c == '-') {
        list.add(i == start ? NumberItem.ZERO : token(inDigits, v.substring(start, i)));
        start = i + 1;
        if (c == '-') {
          list = openSublist(list, opened);
        }
      } else if (Character.isDigit(c)) {
        if (!inDigits && i > start) {
          // A qualifier directly followed by a number ("rc1", "beta2"). The qualifier gets its own
          // sublist so "1.0.0.rc1" sorts like "1.0.0-rc1", and the number starts a further sublist
          // because a letter/digit transition counts as a hyphen.
          if (!list.isEmpty()) {
            list = openSublist(list, opened);
          }
          list.add(new QualifierItem(v.substring(start, i), true));
          start = i;
          list = openSublist(list, opened);
        }
        inDigits = true;
      } else {
        if (inDigits && i > start) {
          list.add(token(true, v.substring(start, i)));
          start = i;
          list = openSublist(list, opened);
        }
        inDigits = false;
      }
    }
    if (v.length() > start) {
      // A trailing ".qualifier" is treated as "-qualifier".
      if (!inDigits && !list.isEmpty()) {
        list = openSublist(list, opened);
      }
      list.add(token(inDigits, v.substring(start)));
    }
    while (!opened.isEmpty()) {
      opened.pop().trimTrailingNulls();
    }
    return root;
  }

  private static ListItem openSublist(ListItem parent, Deque<ListItem> opened) {
    ListItem child = new ListItem();
    parent.add(child);
    opened.push(child);
    return child;
  }

  private static Item token(boolean digits, String text) {
    return digits ? new NumberItem(new BigInteger(text)) : new QualifierItem(text, false);
  }

  // ---------------------------------------------------------------------------------------------
  // Items. compareTo(null) compares against the padding value used when the other version is
  // shorter: 0 for numbers, the release qualifier "" for qualifiers.

  private sealed interface Item permits NumberItem, QualifierItem, ListItem {
    int compareTo(Item other);

    boolean isNull();
  }

  private record NumberItem(BigInteger value) implements Item {
    static final NumberItem ZERO = new NumberItem(BigInteger.ZERO);

    @Override
    public int compareTo(Item other) {
      if (other == null) {
        return value.signum() == 0 ? 0 : 1;
      }
      if (other instanceof NumberItem n) {
        return value.compareTo(n.value);
      }
      // A number sorts after both a qualifier (1.1 > 1-sp) and a sublist (1.1 > 1-1).
      return 1;
    }

    @Override
    public boolean isNull() {
      return value.signum() == 0;
    }

    @Override
    public String toString() {
      return value.toString();
    }
  }

  private static final class QualifierItem implements Item {
    private static final List<String> KNOWN =
        List.of("alpha", "beta", "milestone", "rc", "snapshot", "", "sp");
    private static final int RELEASE_RANK = KNOWN.indexOf("");
    private static final int UNKNOWN_RANK = KNOWN.size();
    private static final Map<String, String> ALIASES =
        Map.of("ga", "", "final", "", "release", "", "cr", "rc");

    private final String value;
    private final int rank;

    QualifierItem(String raw, boolean followedByDigit) {
      String v = raw;
      if (followedByDigit && v.length() == 1) {
        v =
            switch (v.charAt(0)) {
              case 'a' -> "alpha";
              case 'b' -> "beta";
              case 'm' -> "milestone";
              default -> v;
            };
      }
      this.value = ALIASES.getOrDefault(v, v);
      int known = KNOWN.indexOf(this.value);
      this.rank = known >= 0 ? known : UNKNOWN_RANK;
    }

    boolean isPreRelease() {
      return rank < RELEASE_RANK;
    }

    @Override
    public int compareTo(Item other) {
      if (other == null) {
        return Integer.compare(rank, RELEASE_RANK);
      }
      if (other instanceof QualifierItem q) {
        int byRank = Integer.compare(rank, q.rank);
        if (byRank != 0 || rank != UNKNOWN_RANK) {
          return byRank;
        }
        return value.compareTo(q.value);
      }
      // A qualifier sorts before a number (1.any < 1.1) and before a sublist (1.any < 1-1).
      return -1;
    }

    @Override
    public boolean isNull() {
      return rank == RELEASE_RANK;
    }

    @Override
    public boolean equals(Object o) {
      return o instanceof QualifierItem q && value.equals(q.value);
    }

    @Override
    public int hashCode() {
      return value.hashCode();
    }

    @Override
    public String toString() {
      return value;
    }
  }

  private static final class ListItem implements Item {
    private final List<Item> children = new ArrayList<>();

    void add(Item item) {
      children.add(item);
    }

    boolean isEmpty() {
      return children.isEmpty();
    }

    Item get(int i) {
      return children.get(i);
    }

    /** Removes trailing null items; a null item followed only by sublists is also removed. */
    void trimTrailingNulls() {
      for (int i = children.size() - 1; i >= 0; i--) {
        Item last = children.get(i);
        if (last.isNull()) {
          children.remove(i);
        } else if (!(last instanceof ListItem)) {
          break;
        }
      }
    }

    boolean containsPreReleaseQualifier() {
      for (Item child : children) {
        if (child instanceof QualifierItem q && q.isPreRelease()) {
          return true;
        }
        if (child instanceof ListItem l && l.containsPreReleaseQualifier()) {
          return true;
        }
      }
      return false;
    }

    @Override
    public int compareTo(Item other) {
      if (other == null) {
        // Compare every element with padding, not just the first (Maven MNG-6964).
        for (Item child : children) {
          int r = child.compareTo(null);
          if (r != 0) {
            return r;
          }
        }
        return 0;
      }
      if (other instanceof NumberItem) {
        return -1; // 1-1 < 1.1
      }
      if (other instanceof QualifierItem) {
        return 1; // 1-1 > 1-sp
      }
      ListItem right = (ListItem) other;
      int n = Math.max(children.size(), right.children.size());
      for (int i = 0; i < n; i++) {
        Item l = i < children.size() ? children.get(i) : null;
        Item r = i < right.children.size() ? right.children.get(i) : null;
        int result;
        if (l == null) {
          result = r == null ? 0 : -r.compareTo(null);
        } else {
          result = l.compareTo(r);
        }
        if (result != 0) {
          return result;
        }
      }
      return 0;
    }

    @Override
    public boolean isNull() {
      return children.isEmpty();
    }

    @Override
    public boolean equals(Object o) {
      return o instanceof ListItem l && children.equals(l.children);
    }

    @Override
    public int hashCode() {
      return Objects.hash(children);
    }

    @Override
    public String toString() {
      StringBuilder b = new StringBuilder();
      for (Item child : children) {
        if (b.length() > 0) {
          b.append(child instanceof ListItem ? '-' : '.');
        }
        b.append(child);
      }
      return b.toString();
    }
  }
}
