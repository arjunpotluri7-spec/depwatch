package io.github.arjunpotluri7spec.depwatch.util;

/** Helpers for putting untrusted text (advisory summaries, file content) into reports. */
public final class Text {

  private Text() {}

  /**
   * Replaces control characters (including ESC, so terminal escape sequences cannot be injected)
   * with spaces, collapses runs of whitespace and truncates to {@code max} characters.
   */
  public static String clean(String s, int max) {
    if (s == null) {
      return "";
    }
    StringBuilder b = new StringBuilder(Math.min(s.length(), max + 3));
    boolean space = false;
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      if (Character.isISOControl(c) || Character.isWhitespace(c)) {
        if (!space && b.length() > 0) {
          b.append(' ');
        }
        space = true;
        continue;
      }
      space = false;
      b.append(c);
      if (b.length() >= max) {
        return b.substring(0, Math.max(0, max - 3)) + "...";
      }
    }
    return b.toString().strip();
  }

  public static String clean(String s) {
    return clean(s, 500);
  }

  /** Pads or truncates to exactly {@code width} characters. */
  public static String cell(String s, int width) {
    String v = s.length() > width ? s.substring(0, Math.max(0, width - 1)) + "~" : s;
    StringBuilder b = new StringBuilder(v);
    while (b.length() < width) {
      b.append(' ');
    }
    return b.toString();
  }
}
