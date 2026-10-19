package io.github.arjunpotluri7spec.depwatch.license;

/**
 * The policy decision for one package's license expression.
 *
 * @param expression the expression evaluated, or null when the package has no license data
 * @param explanation a sentence saying which licenses decided the outcome
 * @param exception the exception that applied, if any
 */
public record LicenseVerdict(
    Status status, String expression, String explanation, LicenseException exception) {

  /** Ordered from worst to best, which is also how AND (worst) and OR (best) combine them. */
  public enum Status {
    DENIED,
    UNKNOWN,
    REVIEW,
    ALLOWED
  }

  public boolean isFinding() {
    return status != Status.ALLOWED;
  }
}
