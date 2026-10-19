package io.github.arjunpotluri7spec.depwatch.license;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * A small SPDX license expression parser: identifiers (optionally with {@code +}), {@code WITH}
 * exceptions, {@code AND}, {@code OR} and parentheses, with AND binding tighter than OR as in SPDX
 * 2.3 Annex D. Operators are accepted in any case.
 */
public sealed interface SpdxExpression {

  int MAX_LENGTH = 1024;
  int MAX_DEPTH = 32;

  /** A license identifier, e.g. {@code Apache-2.0}, with an optional {@code WITH} exception. */
  record License(String id, String exception) implements SpdxExpression {
    @Override
    public String toString() {
      return exception == null ? id : id + " WITH " + exception;
    }
  }

  record And(SpdxExpression left, SpdxExpression right) implements SpdxExpression {
    @Override
    public String toString() {
      return wrap(left) + " AND " + wrap(right);
    }
  }

  record Or(SpdxExpression left, SpdxExpression right) implements SpdxExpression {
    @Override
    public String toString() {
      return wrap(left) + " OR " + wrap(right);
    }
  }

  private static String wrap(SpdxExpression e) {
    return e instanceof License ? e.toString() : "(" + e + ")";
  }

  /** Every license identifier in the expression, left to right. */
  default List<String> licenseIds() {
    List<String> out = new ArrayList<>();
    collect(this, out);
    return out;
  }

  private static void collect(SpdxExpression e, List<String> out) {
    if (e instanceof License l) {
      out.add(l.id());
    } else if (e instanceof And a) {
      collect(a.left(), out);
      collect(a.right(), out);
    } else if (e instanceof Or o) {
      collect(o.left(), out);
      collect(o.right(), out);
    }
  }

  /**
   * Parses an expression.
   *
   * @throws IllegalArgumentException with a short reason
   */
  static SpdxExpression parse(String text) {
    if (text == null || text.isBlank()) {
      throw new IllegalArgumentException("license expression is empty");
    }
    if (text.length() > MAX_LENGTH) {
      throw new IllegalArgumentException("license expression is too long");
    }
    Parser p = new Parser(tokenize(text));
    SpdxExpression e = p.or(0);
    if (p.pos != p.tokens.size()) {
      throw new IllegalArgumentException(
          "unexpected '" + p.tokens.get(p.pos) + "' in license expression '" + text + "'");
    }
    return e;
  }

  private static List<String> tokenize(String text) {
    List<String> out = new ArrayList<>();
    StringBuilder cur = new StringBuilder();
    for (int i = 0; i < text.length(); i++) {
      char c = text.charAt(i);
      if (c == '(' || c == ')' || Character.isWhitespace(c)) {
        if (cur.length() > 0) {
          out.add(cur.toString());
          cur.setLength(0);
        }
        if (!Character.isWhitespace(c)) {
          out.add(String.valueOf(c));
        }
      } else if (Character.isLetterOrDigit(c) || c == '-' || c == '.' || c == '+' || c == ':') {
        cur.append(c);
      } else {
        throw new IllegalArgumentException("invalid character '" + c + "' in license expression");
      }
    }
    if (cur.length() > 0) {
      out.add(cur.toString());
    }
    return out;
  }

  /** Recursive-descent parser over the token list. */
  final class Parser {
    private final List<String> tokens;
    private int pos;

    private Parser(List<String> tokens) {
      this.tokens = tokens;
    }

    private boolean isOp(String op) {
      return pos < tokens.size() && tokens.get(pos).toUpperCase(Locale.ROOT).equals(op);
    }

    private SpdxExpression or(int depth) {
      SpdxExpression left = and(depth);
      while (isOp("OR")) {
        pos++;
        left = new Or(left, and(depth));
      }
      return left;
    }

    private SpdxExpression and(int depth) {
      SpdxExpression left = term(depth);
      while (isOp("AND")) {
        pos++;
        left = new And(left, term(depth));
      }
      return left;
    }

    private SpdxExpression term(int depth) {
      if (depth > MAX_DEPTH) {
        throw new IllegalArgumentException("license expression is nested too deeply");
      }
      if (pos >= tokens.size()) {
        throw new IllegalArgumentException("license expression ends unexpectedly");
      }
      String t = tokens.get(pos);
      if (t.equals("(")) {
        pos++;
        SpdxExpression inner = or(depth + 1);
        if (pos >= tokens.size() || !tokens.get(pos).equals(")")) {
          throw new IllegalArgumentException("missing ')' in license expression");
        }
        pos++;
        return inner;
      }
      if (t.equals(")") || isOp("AND") || isOp("OR") || isOp("WITH")) {
        throw new IllegalArgumentException("expected a license identifier, found '" + t + "'");
      }
      pos++;
      String exception = null;
      if (isOp("WITH")) {
        pos++;
        if (pos >= tokens.size() || tokens.get(pos).equals("(") || tokens.get(pos).equals(")")) {
          throw new IllegalArgumentException("WITH must be followed by an exception identifier");
        }
        exception = tokens.get(pos++);
      }
      return new License(t, exception);
    }
  }
}
