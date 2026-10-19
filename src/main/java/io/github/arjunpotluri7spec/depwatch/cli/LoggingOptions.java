package io.github.arjunpotluri7spec.depwatch.cli;

import java.io.PrintWriter;
import picocli.CommandLine.Option;

/** Logging options shared by every command. */
public final class LoggingOptions {

  @Option(
      names = "--log-level",
      paramLabel = "LEVEL",
      description = "Diagnostics on stderr at or above: debug, info, warn (default), error.",
      defaultValue = "warn")
  CliLogger.Level level;

  @Option(
      names = "--log-format",
      paramLabel = "FORMAT",
      description = "Diagnostics format: text (default) or json (one object per line).",
      defaultValue = "text")
  CliLogger.Format format;

  CliLogger logger(PrintWriter err) {
    return new CliLogger(err, level, format);
  }
}
