package io.github.arjunpotluri7spec.depwatch.input;

import io.github.arjunpotluri7spec.depwatch.util.DepwatchException;
import io.github.arjunpotluri7spec.depwatch.util.Limits;
import io.github.arjunpotluri7spec.depwatch.util.SafeFiles;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Pattern;

/** Detects an input file's format and parses it. Files are only read, never executed. */
public final class InputReader {

  private static final Pattern LOCK_LINE =
      Pattern.compile("^[^\\s:=#]+:[^\\s:=]+:[^\\s:=]+=.*$", Pattern.MULTILINE);

  private InputReader() {}

  /**
   * Reads and parses one input.
   *
   * @param forced the format to use, or empty to detect it
   * @throws DepwatchException if the file cannot be read, its format cannot be determined, or it is
   *     rejected as a whole (for example an XML file with a DOCTYPE)
   */
  public static ParsedInput read(Path path, Optional<InputFormat> forced, Limits limits) {
    String name = path.toString();
    byte[] data = SafeFiles.readBytes(path, limits.maxFileBytes());
    InputFormat format = forced.orElseGet(() -> detect(path, data));
    return switch (format) {
      case MAVEN_POM -> PomParser.parse(data, name);
      case GRADLE_LOCKFILE -> GradleLockfileParser.parse(SafeFiles.decodeUtf8(data, name), name);
      case CYCLONEDX_JSON -> CycloneDxParser.parse(SafeFiles.decodeUtf8(data, name), name);
    };
  }

  /**
   * Detection order: well-known file names ({@code pom.xml}, {@code *.pom}, {@code
   * gradle.lockfile}, {@code *.lockfile}, {@code *.cdx.json}, {@code bom.json}), then content (an
   * XML {@code <project>} root, a JSON object with {@code "bomFormat"}, lines shaped like {@code
   * g:a:v=...}).
   *
   * @throws DepwatchException if nothing matches
   */
  public static InputFormat detect(Path path, byte[] data) {
    String file = path.getFileName() == null ? "" : path.getFileName().toString();
    String lower = file.toLowerCase(Locale.ROOT);
    if (lower.equals("pom.xml") || lower.endsWith(".pom")) {
      return InputFormat.MAVEN_POM;
    }
    if (lower.equals("gradle.lockfile") || lower.endsWith(".lockfile")) {
      return InputFormat.GRADLE_LOCKFILE;
    }
    if (lower.endsWith(".cdx.json")
        || lower.equals("bom.json")
        || lower.endsWith(".cyclonedx.json")) {
      return InputFormat.CYCLONEDX_JSON;
    }
    String head =
        new String(data, 0, Math.min(data.length, 64 * 1024), StandardCharsets.UTF_8).strip();
    if (head.startsWith("﻿")) {
      head = head.substring(1);
    }
    if (head.startsWith("<") && head.contains("<project")) {
      return InputFormat.MAVEN_POM;
    }
    if (head.startsWith("{") && head.contains("\"bomFormat\"")) {
      return InputFormat.CYCLONEDX_JSON;
    }
    if (LOCK_LINE.matcher(head).find()) {
      return InputFormat.GRADLE_LOCKFILE;
    }
    throw new DepwatchException(
        path
            + ": cannot tell the input format from the name or content; use --input-type"
            + " pom|gradle-lockfile|cyclonedx");
  }
}
