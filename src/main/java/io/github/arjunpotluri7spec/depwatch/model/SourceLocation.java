package io.github.arjunpotluri7spec.depwatch.model;

/** A file and a 1-based line number. A line of 0 means the line is not known. */
public record SourceLocation(String file, int line) {

  public SourceLocation {
    if (line < 0) {
      throw new IllegalArgumentException("line must be >= 0");
    }
  }

  public static SourceLocation of(String file, int line) {
    return new SourceLocation(file, line);
  }

  @Override
  public String toString() {
    return line > 0 ? file + ":" + line : file;
  }
}
