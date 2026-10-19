package io.github.arjunpotluri7spec.depwatch.cli;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import picocli.CommandLine;

/** Reads the version stamped into the jar at build time. */
public final class VersionProvider implements CommandLine.IVersionProvider {

  /** The tool version, or {@code unknown} when running from an unpackaged build. */
  public static String version() {
    try (InputStream in =
        VersionProvider.class.getResourceAsStream("/depwatch-version.properties")) {
      if (in == null) {
        return "unknown";
      }
      Properties p = new Properties();
      p.load(in);
      return p.getProperty("version", "unknown");
    } catch (IOException e) {
      return "unknown";
    }
  }

  @Override
  public String[] getVersion() {
    return new String[] {"depwatch " + version()};
  }
}
