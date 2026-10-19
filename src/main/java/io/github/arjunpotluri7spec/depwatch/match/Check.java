package io.github.arjunpotluri7spec.depwatch.match;

import io.github.arjunpotluri7spec.depwatch.advisory.Advisory;

/**
 * The result of checking one version against one advisory, with a sentence saying why.
 *
 * @param matchedRange interval notation (or {@code versions list}) of the part that matched; empty
 *     when not affected
 */
public record Check(Advisory advisory, Status status, String reason, String matchedRange) {

  public enum Status {
    AFFECTED,
    NOT_AFFECTED,
    WITHDRAWN
  }

  public boolean affected() {
    return status == Status.AFFECTED;
  }
}
