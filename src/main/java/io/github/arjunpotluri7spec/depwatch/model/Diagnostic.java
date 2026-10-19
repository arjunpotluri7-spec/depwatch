package io.github.arjunpotluri7spec.depwatch.model;

/**
 * A problem found while reading inputs, the advisory database or the configuration. Diagnostics are
 * reported, never thrown, so one bad record or file does not stop the whole run.
 */
public record Diagnostic(Level level, String file, int line, String message) {

  public enum Level {
    INFO,
    WARN,
    ERROR
  }

  public static Diagnostic warn(String file, int line, String message) {
    return new Diagnostic(Level.WARN, file, line, message);
  }

  public static Diagnostic warn(String file, String message) {
    return new Diagnostic(Level.WARN, file, 0, message);
  }

  public static Diagnostic error(String file, String message) {
    return new Diagnostic(Level.ERROR, file, 0, message);
  }

  public static Diagnostic info(String file, String message) {
    return new Diagnostic(Level.INFO, file, 0, message);
  }

  /** {@code file:line: message}, omitting parts that are not known. */
  public String render() {
    StringBuilder b = new StringBuilder();
    if (file != null) {
      b.append(file);
      if (line > 0) {
        b.append(':').append(line);
      }
      b.append(": ");
    }
    return b.append(message).toString();
  }
}
