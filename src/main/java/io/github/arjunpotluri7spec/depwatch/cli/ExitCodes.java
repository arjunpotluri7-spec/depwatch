package io.github.arjunpotluri7spec.depwatch.cli;

/** Process exit codes. */
public final class ExitCodes {
  /** Ran fine, nothing at or above the threshold. */
  public static final int OK = 0;

  /** Findings at or above {@code --fail-on} (or: affected / not in range, for explain/in-range). */
  public static final int FINDINGS = 1;

  /** Usage, configuration or input error, including a rejected input file. */
  public static final int ERROR = 2;

  private ExitCodes() {}
}
