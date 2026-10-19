package io.github.arjunpotluri7spec.depwatch.input;

import io.github.arjunpotluri7spec.depwatch.model.Coordinate;
import io.github.arjunpotluri7spec.depwatch.model.Dependency;
import io.github.arjunpotluri7spec.depwatch.model.Diagnostic;
import io.github.arjunpotluri7spec.depwatch.model.SourceLocation;
import io.github.arjunpotluri7spec.depwatch.version.MavenVersion;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Reads a Gradle dependency lockfile ({@code gradle.lockfile}): one {@code
 * group:artifact:version=configuration,...} entry per line, {@code #} comments, and an {@code
 * empty=} line listing configurations without dependencies.
 *
 * <p>An entry counts as a development dependency when every configuration it belongs to has {@code
 * test} in its name (for example {@code testRuntimeClasspath}).
 */
public final class GradleLockfileParser {

  private GradleLockfileParser() {}

  public static ParsedInput parse(String text, String file) {
    List<Dependency> out = new ArrayList<>();
    List<Diagnostic> diags = new ArrayList<>();
    int unusable = 0;
    int lineNo = 0;
    for (String rawLine : text.split("\r?\n", -1)) {
      lineNo++;
      String line = rawLine.strip();
      if (line.isEmpty() || line.startsWith("#") || line.startsWith("empty=")) {
        continue;
      }
      int eq = line.indexOf('=');
      String gav = eq < 0 ? line : line.substring(0, eq);
      String confs = eq < 0 ? "" : line.substring(eq + 1);
      String[] parts = gav.split(":", -1);
      if (parts.length != 3) {
        unusable++;
        diags.add(
            Diagnostic.warn(
                file, lineNo, "expected group:artifact:version=configurations; line skipped"));
        continue;
      }
      try {
        Coordinate c = new Coordinate(parts[0], parts[1]);
        MavenVersion v = MavenVersion.parse(parts[2]);
        boolean dev = isDevOnly(confs);
        out.add(
            new Dependency(c, v, confs, dev, "lockfile", SourceLocation.of(file, lineNo), null));
      } catch (IllegalArgumentException e) {
        unusable++;
        diags.add(Diagnostic.warn(file, lineNo, e.getMessage() + "; line skipped"));
      }
    }
    return new ParsedInput(file, InputFormat.GRADLE_LOCKFILE, out, diags, unusable, false);
  }

  static boolean isDevOnly(String configurations) {
    if (configurations.isBlank()) {
      return false;
    }
    for (String c : configurations.split(",")) {
      if (!c.strip().toLowerCase(Locale.ROOT).contains("test")) {
        return false;
      }
    }
    return true;
  }
}
