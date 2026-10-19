package io.github.arjunpotluri7spec.depwatch.version;

/** A version or version range string that cannot be used. The message is safe to show users. */
public class InvalidVersionException extends IllegalArgumentException {
  private static final long serialVersionUID = 1L;

  public InvalidVersionException(String message) {
    super(message);
  }
}
