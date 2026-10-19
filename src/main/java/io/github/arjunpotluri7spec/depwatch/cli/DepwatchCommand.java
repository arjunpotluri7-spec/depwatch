package io.github.arjunpotluri7spec.depwatch.cli;

import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Spec;

/** The {@code depwatch} root command. */
@Command(
    name = "depwatch",
    mixinStandardHelpOptions = true,
    versionProvider = VersionProvider.class,
    description = {
      "Offline dependency auditor: checks Maven dependencies against a local OSV advisory"
          + " snapshot and a license policy, and explains every finding.",
      "",
      "Nothing is fetched from the network; the advisory database is a folder you provide."
    },
    subcommands = {ScanCommand.class, ExplainCommand.class, VersionCommand.class, DbCommand.class},
    footer = {
      "",
      "Exit codes: 0 = no findings at or above --fail-on; 1 = findings at or above it;",
      "2 = usage, configuration or input error (including a rejected input file)."
    })
public final class DepwatchCommand implements Callable<Integer> {

  @Spec CommandSpec spec;

  /** Without a subcommand: print usage to stderr and exit 2. */
  @Override
  public Integer call() {
    spec.commandLine().usage(spec.commandLine().getErr());
    return ExitCodes.ERROR;
  }
}
