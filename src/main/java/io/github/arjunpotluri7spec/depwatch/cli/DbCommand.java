package io.github.arjunpotluri7spec.depwatch.cli;

import io.github.arjunpotluri7spec.depwatch.advisory.AdvisoryDatabase;
import io.github.arjunpotluri7spec.depwatch.model.Severity;
import java.io.PrintWriter;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Spec;

/** {@code depwatch db stats}. */
@Command(
    name = "db",
    mixinStandardHelpOptions = true,
    versionProvider = VersionProvider.class,
    description = "Inspect an advisory database folder.",
    subcommands = {DbCommand.Stats.class})
public final class DbCommand implements Callable<Integer> {

  @Spec CommandSpec spec;

  @Override
  public Integer call() {
    spec.commandLine().usage(spec.commandLine().getErr());
    return ExitCodes.ERROR;
  }

  /** {@code depwatch db stats --db DIR}. */
  @Command(
      name = "stats",
      mixinStandardHelpOptions = true,
      versionProvider = VersionProvider.class,
      description = "Load the database and print counts; malformed records are listed as warnings.",
      footer = {"", "Exit codes: 0 = loaded, 2 = directory missing or has no JSON files."})
  public static final class Stats implements Callable<Integer> {
    @Spec CommandSpec spec;

    @Mixin LoggingOptions logging;

    @Mixin CommonDbOptions dbOptions;

    @Override
    public Integer call() {
      CliLogger log = logging.logger(spec.commandLine().getErr());
      AdvisoryDatabase db = dbOptions.load(log);
      AdvisoryDatabase.Stats s = db.stats();
      PrintWriter out = spec.commandLine().getOut();
      out.println("Advisory database: " + s.location());
      out.printf("  files read:            %d%n", s.filesRead());
      out.printf("  Maven advisories:      %d (%d withdrawn)%n", s.recordsLoaded(), s.withdrawn());
      out.printf("  skipped (malformed):   %d%n", s.recordsSkipped());
      out.printf("  non-Maven records:     %d (ignored)%n", s.nonMavenRecords());
      out.printf("  packages:              %d%n", s.packages());
      StringBuilder sev = new StringBuilder();
      for (Severity v :
          new Severity[] {
            Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.UNKNOWN
          }) {
        if (sev.length() > 0) {
          sev.append(", ");
        }
        sev.append(v.label()).append(' ').append(s.bySeverity().get(v));
      }
      out.println("  by severity (active):  " + sev);
      out.printf("  with a fix version:    %d%n", s.withFix());
      out.printf("  without a fix version: %d%n", s.withoutFix());
      out.flush();
      return ExitCodes.OK;
    }
  }
}
