package io.github.arjunpotluri7spec.depwatch.util;

/**
 * An error caused by the user's input, configuration or environment. The message is a single line
 * that names the file and the problem, and is shown to the user as is (never with a stack trace).
 */
public class DepwatchException extends RuntimeException {
  private static final long serialVersionUID = 1L;

  public DepwatchException(String message) {
    super(message);
  }

  public DepwatchException(String message, Throwable cause) {
    super(message, cause);
  }
}
