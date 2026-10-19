package io.github.arjunpotluri7spec.depwatch.util;

/**
 * Resource limits applied to everything Depwatch reads.
 *
 * @param maxFileBytes largest single file read (inputs, config, each database file)
 * @param maxDbFiles most {@code *.json} files loaded from the advisory database
 * @param followSymlinks whether symbolic links inside the database directory are followed
 */
public record Limits(long maxFileBytes, int maxDbFiles, boolean followSymlinks) {

  public static final long DEFAULT_MAX_FILE_BYTES = 32L * 1024 * 1024;
  public static final int DEFAULT_MAX_DB_FILES = 200_000;

  public Limits {
    if (maxFileBytes <= 0) {
      throw new IllegalArgumentException("maxFileBytes must be positive");
    }
    if (maxDbFiles <= 0) {
      throw new IllegalArgumentException("maxDbFiles must be positive");
    }
  }

  public static Limits defaults() {
    return new Limits(DEFAULT_MAX_FILE_BYTES, DEFAULT_MAX_DB_FILES, false);
  }
}
