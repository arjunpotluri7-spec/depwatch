package io.github.arjunpotluri7spec.depwatch.input;

import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Expands {@code ${name}} placeholders using POM properties. Nesting is bounded to {@link
 * #MAX_DEPTH} levels and cycles ({@code a -> b -> a}) are detected. Placeholders that cannot be
 * expanded are left in place and reported. Environment ({@code env.*}) and system properties are
 * never consulted, so results do not depend on the machine running the scan.
 */
public final class PropertyResolver {

  public static final int MAX_DEPTH = 10;
  private static final int MAX_RESULT = 4096;
  private static final int MAX_EXPANSIONS = 10_000;

  /** An expanded value and the problems met, if any. */
  public record Result(String value, List<String> problems) {
    public boolean complete() {
      return problems.isEmpty() && !value.contains("${");
    }
  }

  private final Map<String, String> properties;
  private int expansions;

  public PropertyResolver(Map<String, String> properties) {
    this.properties = Map.copyOf(properties);
  }

  public Result resolve(String text) {
    Set<String> problems = new LinkedHashSet<>();
    expansions = 0;
    String value = expand(text, 0, new HashSet<>(), problems);
    return new Result(value, List.copyOf(problems));
  }

  private String expand(String text, int depth, Set<String> active, Set<String> problems) {
    if (text == null || !text.contains("${")) {
      return text;
    }
    StringBuilder out = new StringBuilder();
    int i = 0;
    while (i < text.length()) {
      int open = text.indexOf("${", i);
      if (open < 0) {
        out.append(text, i, text.length());
        break;
      }
      int close = text.indexOf('}', open + 2);
      if (close < 0) {
        problems.add("unterminated placeholder in '" + text + "'");
        out.append(text, i, text.length());
        break;
      }
      out.append(text, i, open);
      String name = text.substring(open + 2, close).trim();
      String literal = text.substring(open, close + 1);
      if (name.startsWith("env.")) {
        problems.add("${" + name + "} is an environment variable, which is never read");
        out.append(literal);
      } else if (active.contains(name)) {
        problems.add("property cycle through ${" + name + "}");
        out.append(literal);
      } else if (depth >= MAX_DEPTH) {
        problems.add("properties nested deeper than " + MAX_DEPTH + " levels at ${" + name + "}");
        out.append(literal);
      } else if (++expansions > MAX_EXPANSIONS) {
        problems.add("more than " + MAX_EXPANSIONS + " property expansions");
        out.append(literal);
      } else if (!properties.containsKey(name)) {
        problems.add("property ${" + name + "} is not defined in this POM");
        out.append(literal);
      } else {
        active.add(name);
        out.append(expand(properties.get(name), depth + 1, active, problems));
        active.remove(name);
      }
      if (out.length() > MAX_RESULT) {
        problems.add("expanded value is longer than " + MAX_RESULT + " characters");
        return out.substring(0, MAX_RESULT);
      }
      i = close + 1;
    }
    return out.toString();
  }
}
