package io.github.arjunpotluri7spec.depwatch.util;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;

/** Size-limited, read-only file access. */
public final class SafeFiles {

  private SafeFiles() {}

  /**
   * Reads a regular file of at most {@code maxBytes} bytes. The size is checked before reading and
   * again while reading, so a file that grows in between cannot exceed the limit.
   *
   * @throws DepwatchException naming the file and the problem
   */
  public static byte[] readBytes(Path file, long maxBytes) {
    try {
      if (!Files.exists(file)) {
        throw new DepwatchException(file + ": file not found");
      }
      if (!Files.isRegularFile(file)) {
        throw new DepwatchException(file + ": not a regular file");
      }
      long size = Files.size(file);
      if (size > maxBytes) {
        throw new DepwatchException(
            file + ": file is " + size + " bytes, larger than the limit of " + maxBytes + " bytes");
      }
      try (InputStream in = Files.newInputStream(file)) {
        byte[] data = in.readNBytes((int) Math.min(maxBytes + 1, Integer.MAX_VALUE - 8));
        if (data.length > maxBytes) {
          throw new DepwatchException(
              file + ": file grew past the limit of " + maxBytes + " bytes");
        }
        return data;
      }
    } catch (NoSuchFileException e) {
      throw new DepwatchException(file + ": file not found", e);
    } catch (IOException e) {
      throw new DepwatchException(file + ": cannot read file (" + e.getMessage() + ")", e);
    }
  }

  /** Reads a UTF-8 text file (a leading byte-order mark is dropped). Invalid UTF-8 is an error. */
  public static String readUtf8(Path file, long maxBytes) {
    return decodeUtf8(readBytes(file, maxBytes), file.toString());
  }

  /** Decodes UTF-8 strictly, dropping a leading byte-order mark. */
  public static String decodeUtf8(byte[] data, String file) {
    int offset = 0;
    if (data.length >= 3
        && (data[0] & 0xFF) == 0xEF
        && (data[1] & 0xFF) == 0xBB
        && (data[2] & 0xFF) == 0xBF) {
      offset = 3;
    }
    try {
      return StandardCharsets.UTF_8
          .newDecoder()
          .onMalformedInput(CodingErrorAction.REPORT)
          .onUnmappableCharacter(CodingErrorAction.REPORT)
          .decode(ByteBuffer.wrap(data, offset, data.length - offset))
          .toString();
    } catch (CharacterCodingException e) {
      throw new DepwatchException(file + ": file is not valid UTF-8", e);
    }
  }

  public static boolean isSymlink(Path p) {
    return Files.isSymbolicLink(p);
  }

  public static boolean isRegularNoFollow(Path p) {
    return Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS);
  }
}
