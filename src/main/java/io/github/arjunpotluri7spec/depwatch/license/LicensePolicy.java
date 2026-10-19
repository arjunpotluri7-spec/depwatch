package io.github.arjunpotluri7spec.depwatch.license;

import io.github.arjunpotluri7spec.depwatch.model.Coordinate;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

/**
 * Allowed, review-required and denied SPDX license ids plus per-package exceptions.
 *
 * <p>Identifiers match case-insensitively, as SPDX specifies. {@code X WITH exception} is judged by
 * {@code X}. For {@code A OR B} the better outcome wins (you may choose either license); for {@code
 * A AND B} the worse one wins (you must comply with both). A license on no list is unknown.
 */
public final class LicensePolicy {

  private final Set<String> allowed;
  private final Set<String> review;
  private final Set<String> denied;
  private final List<LicenseException> exceptions;

  public LicensePolicy(
      Set<String> allowed,
      Set<String> review,
      Set<String> denied,
      List<LicenseException> exceptions) {
    this.allowed = normalize(allowed);
    this.review = normalize(review);
    this.denied = normalize(denied);
    this.exceptions = List.copyOf(exceptions);
    for (String id : this.allowed) {
      if (this.denied.contains(id) || this.review.contains(id)) {
        throw new IllegalArgumentException("license " + id + " is on more than one list");
      }
    }
    for (String id : this.review) {
      if (this.denied.contains(id)) {
        throw new IllegalArgumentException("license " + id + " is on more than one list");
      }
    }
  }

  private static Set<String> normalize(Set<String> ids) {
    return ids.stream()
        .map(s -> s.trim().toLowerCase(Locale.ROOT))
        .collect(Collectors.toCollection(TreeSet::new));
  }

  public List<LicenseException> exceptions() {
    return exceptions;
  }

  public int size() {
    return allowed.size() + review.size() + denied.size();
  }

  /** Classifies one license id, ignoring exceptions. */
  public LicenseVerdict.Status classify(String id) {
    String key = id.toLowerCase(Locale.ROOT);
    if (denied.contains(key)) {
      return LicenseVerdict.Status.DENIED;
    }
    if (allowed.contains(key)) {
      return LicenseVerdict.Status.ALLOWED;
    }
    if (review.contains(key)) {
      return LicenseVerdict.Status.REVIEW;
    }
    return LicenseVerdict.Status.UNKNOWN;
  }

  /**
   * Evaluates a package's license expression.
   *
   * @param expression SPDX expression, or null if the package has no license information
   */
  public LicenseVerdict evaluate(Coordinate pkg, String expression) {
    Optional<LicenseException> whole =
        exceptions.stream()
            .filter(e -> e.coordinate().equals(pkg) && e.license() == null)
            .findFirst();
    if (whole.isPresent()) {
      return new LicenseVerdict(
          LicenseVerdict.Status.ALLOWED,
          expression,
          "accepted by a policy exception for " + pkg + ": " + whole.get().reason(),
          whole.get());
    }
    if (expression == null || expression.isBlank()) {
      return new LicenseVerdict(
          LicenseVerdict.Status.UNKNOWN, null, "no license information for " + pkg, null);
    }
    SpdxExpression parsed;
    try {
      parsed = SpdxExpression.parse(expression);
    } catch (IllegalArgumentException e) {
      return new LicenseVerdict(
          LicenseVerdict.Status.UNKNOWN,
          expression,
          "license expression could not be parsed: " + e.getMessage(),
          null);
    }
    List<LicenseException> used = new ArrayList<>();
    LicenseVerdict.Status status = eval(parsed, pkg, used);
    LicenseException applied = used.isEmpty() ? null : used.get(0);
    return new LicenseVerdict(status, expression, explain(parsed, pkg, status, applied), applied);
  }

  private LicenseVerdict.Status eval(
      SpdxExpression e, Coordinate pkg, List<LicenseException> used) {
    if (e instanceof SpdxExpression.License l) {
      LicenseVerdict.Status s = classify(baseId(l.id()));
      if (s != LicenseVerdict.Status.ALLOWED) {
        for (LicenseException ex : exceptions) {
          if (ex.coordinate().equals(pkg)
              && ex.license() != null
              && ex.license().equalsIgnoreCase(l.id())) {
            used.add(ex);
            return LicenseVerdict.Status.ALLOWED;
          }
        }
      }
      return s;
    }
    if (e instanceof SpdxExpression.And a) {
      LicenseVerdict.Status l = eval(a.left(), pkg, used);
      LicenseVerdict.Status r = eval(a.right(), pkg, used);
      return l.compareTo(r) <= 0 ? l : r;
    }
    SpdxExpression.Or o = (SpdxExpression.Or) e;
    LicenseVerdict.Status l = eval(o.left(), pkg, used);
    LicenseVerdict.Status r = eval(o.right(), pkg, used);
    return l.compareTo(r) >= 0 ? l : r;
  }

  /** {@code GPL-2.0+} is judged as written first; if unlisted, by {@code GPL-2.0-or-later}. */
  private String baseId(String id) {
    if (id.endsWith("+") && classify(id) == LicenseVerdict.Status.UNKNOWN) {
      return id.substring(0, id.length() - 1) + "-or-later";
    }
    return id;
  }

  private String explain(
      SpdxExpression e, Coordinate pkg, LicenseVerdict.Status status, LicenseException applied) {
    List<String> parts = new ArrayList<>();
    Set<String> seen = new TreeSet<>(Comparator.naturalOrder());
    for (String id : e.licenseIds()) {
      if (seen.add(id)) {
        parts.add(id + " is " + describe(classify(baseId(id))));
      }
    }
    String text = String.join(", ", parts);
    String verdict =
        switch (status) {
          case ALLOWED -> "allowed";
          case REVIEW -> "needs review";
          case DENIED -> "denied";
          case UNKNOWN -> "not covered by the policy";
        };
    String ex =
        applied == null
            ? ""
            : "; "
                + applied.license()
                + " accepted for "
                + pkg
                + " by exception: "
                + applied.reason();
    if (e instanceof SpdxExpression.License) {
      return text + ex;
    }
    return text + ", so '" + e + "' is " + verdict + ex;
  }

  private static String describe(LicenseVerdict.Status s) {
    return switch (s) {
      case ALLOWED -> "on the allowed list";
      case REVIEW -> "on the review-required list";
      case DENIED -> "on the denied list";
      case UNKNOWN -> "not on any policy list";
    };
  }
}
