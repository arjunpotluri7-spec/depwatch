package io.github.arjunpotluri7spec.depwatch.input;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * A minimal Package URL parser (https://github.com/package-url/purl-spec), enough to read {@code
 * pkg:maven/group/artifact@version} and to recognise other types.
 *
 * @param namespace for Maven, the groupId; may be empty
 * @param version may be empty
 */
public record PackageUrl(String type, String namespace, String name, String version) {

  /**
   * Parses a purl.
   *
   * @throws IllegalArgumentException with a short reason
   */
  public static PackageUrl parse(String purl) {
    if (purl == null || purl.length() > 2048) {
      throw new IllegalArgumentException("purl is missing or too long");
    }
    String s = purl.strip();
    if (!s.regionMatches(true, 0, "pkg:", 0, 4)) {
      throw new IllegalArgumentException("purl '" + purl + "' does not start with pkg:");
    }
    s = s.substring(4);
    while (s.startsWith("/")) {
      s = s.substring(1);
    }
    int hash = s.indexOf('#');
    if (hash >= 0) {
      s = s.substring(0, hash);
    }
    int q = s.indexOf('?');
    if (q >= 0) {
      s = s.substring(0, q);
    }
    int slash = s.indexOf('/');
    if (slash <= 0) {
      throw new IllegalArgumentException("purl '" + purl + "' has no type/name");
    }
    String type = s.substring(0, slash).toLowerCase(Locale.ROOT);
    String rest = s.substring(slash + 1);
    String version = "";
    int at = rest.lastIndexOf('@');
    if (at >= 0) {
      version = decode(rest.substring(at + 1));
      rest = rest.substring(0, at);
    }
    while (rest.endsWith("/")) {
      rest = rest.substring(0, rest.length() - 1);
    }
    int lastSlash = rest.lastIndexOf('/');
    String name = decode(lastSlash < 0 ? rest : rest.substring(lastSlash + 1));
    String namespace = lastSlash < 0 ? "" : decodePath(rest.substring(0, lastSlash));
    if (name.isEmpty()) {
      throw new IllegalArgumentException("purl '" + purl + "' has an empty name");
    }
    return new PackageUrl(type, namespace, name, version);
  }

  private static String decodePath(String path) {
    StringBuilder b = new StringBuilder();
    for (String seg : path.split("/")) {
      if (seg.isEmpty()) {
        continue;
      }
      if (b.length() > 0) {
        b.append('/');
      }
      b.append(decode(seg));
    }
    return b.toString();
  }

  /** Percent-decoding without treating '+' as a space (purls are not form-encoded). */
  static String decode(String s) {
    if (s.indexOf('%') < 0) {
      return s;
    }
    StringBuilder out = new StringBuilder();
    ByteArrayOutputStream pending = new ByteArrayOutputStream();
    int i = 0;
    while (i < s.length()) {
      char c = s.charAt(i);
      if (c == '%' && i + 2 < s.length()) {
        int hi = Character.digit(s.charAt(i + 1), 16);
        int lo = Character.digit(s.charAt(i + 2), 16);
        if (hi >= 0 && lo >= 0) {
          pending.write(hi * 16 + lo);
          i += 3;
          continue;
        }
      }
      if (pending.size() > 0) {
        out.append(pending.toString(StandardCharsets.UTF_8));
        pending.reset();
      }
      out.append(c);
      i++;
    }
    if (pending.size() > 0) {
      out.append(pending.toString(StandardCharsets.UTF_8));
    }
    return out.toString();
  }
}
