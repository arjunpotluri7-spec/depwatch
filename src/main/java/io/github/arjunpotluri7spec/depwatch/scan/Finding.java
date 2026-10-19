package io.github.arjunpotluri7spec.depwatch.scan;

import io.github.arjunpotluri7spec.depwatch.advisory.Advisory;
import io.github.arjunpotluri7spec.depwatch.license.LicenseVerdict;
import io.github.arjunpotluri7spec.depwatch.match.UpgradeSuggestion;
import io.github.arjunpotluri7spec.depwatch.model.Dependency;
import io.github.arjunpotluri7spec.depwatch.model.Severity;
import java.util.Comparator;

/**
 * One reported problem.
 *
 * @param ruleId the advisory id for vulnerabilities; {@code license-denied}, {@code
 *     license-unknown} or {@code license-review} for license findings
 * @param why a sentence explaining exactly why this finding exists
 * @param matchedRange for vulnerabilities, the interval (or {@code versions list}) that matched
 * @param advisory set for vulnerability findings
 * @param fix the smallest safe upgrade, for vulnerability findings
 * @param license set for license findings
 * @param suppressedReason set when a configured suppression accepted this finding
 */
public record Finding(
    Type type,
    String ruleId,
    Severity severity,
    Dependency dependency,
    String title,
    String why,
    String matchedRange,
    Advisory advisory,
    UpgradeSuggestion fix,
    LicenseVerdict license,
    String suppressedReason) {

  public enum Type {
    VULNERABILITY,
    LICENSE
  }

  public static final String LICENSE_DENIED = "license-denied";
  public static final String LICENSE_UNKNOWN = "license-unknown";
  public static final String LICENSE_REVIEW = "license-review";

  /** Most severe first, then by package, version, rule and location, for stable reports. */
  public static final Comparator<Finding> ORDER =
      Comparator.comparing((Finding f) -> f.severity().sortRank())
          .reversed()
          .thenComparing(f -> f.type().ordinal())
          .thenComparing(f -> f.dependency().coordinate())
          .thenComparing(f -> f.dependency().version())
          .thenComparing(Finding::ruleId)
          .thenComparing(f -> f.dependency().location().file())
          .thenComparing(f -> f.dependency().location().line());

  public boolean suppressed() {
    return suppressedReason != null;
  }
}
