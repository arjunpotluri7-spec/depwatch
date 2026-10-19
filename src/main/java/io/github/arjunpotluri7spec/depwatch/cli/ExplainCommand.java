package io.github.arjunpotluri7spec.depwatch.cli;

import io.github.arjunpotluri7spec.depwatch.advisory.AdvisoryDatabase;
import io.github.arjunpotluri7spec.depwatch.match.AdvisoryMatcher;
import io.github.arjunpotluri7spec.depwatch.match.Check;
import io.github.arjunpotluri7spec.depwatch.match.UpgradeAdvisor;
import io.github.arjunpotluri7spec.depwatch.match.UpgradeSuggestion;
import io.github.arjunpotluri7spec.depwatch.model.Coordinate;
import io.github.arjunpotluri7spec.depwatch.util.DepwatchException;
import io.github.arjunpotluri7spec.depwatch.util.Text;
import io.github.arjunpotluri7spec.depwatch.version.MavenVersion;
import java.io.PrintWriter;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;

/** {@code depwatch explain group:artifact:version}. */
@Command(
    name = "explain",
    mixinStandardHelpOptions = true,
    versionProvider = VersionProvider.class,
    description =
        "Show every advisory for a package, whether it matches and why, and the smallest safe upgrade.",
    footer = {"", "Exit codes: 0 = not affected, 1 = affected, 2 = error."})
public final class ExplainCommand implements Callable<Integer> {

  @Spec CommandSpec spec;

  @Mixin LoggingOptions logging;

  @Mixin CommonDbOptions dbOptions;

  @Parameters(paramLabel = "GROUP:ARTIFACT:VERSION", description = "The dependency to explain.")
  String gav;

  @Override
  public Integer call() {
    CliLogger log = logging.logger(spec.commandLine().getErr());
    String[] parts = gav.split(":", -1);
    if (parts.length != 3) {
      throw new DepwatchException("'" + gav + "' is not in group:artifact:version form");
    }
    Coordinate c;
    MavenVersion v;
    try {
      c = new Coordinate(parts[0], parts[1]);
      v = MavenVersion.parse(parts[2]);
    } catch (IllegalArgumentException e) {
      throw new DepwatchException("'" + gav + "': " + e.getMessage());
    }
    AdvisoryDatabase db = dbOptions.load(log);
    PrintWriter out = spec.commandLine().getOut();
    List<Check> checks = AdvisoryMatcher.checkAll(db, c, v);
    out.println(c + ":" + v);
    out.println(
        "Advisories naming "
            + c
            + ": "
            + checks.size()
            + " (of "
            + db.advisories().size()
            + " Maven advisories in "
            + db.location()
            + ")");
    out.println("Version canonical form: " + v.canonical());
    out.println();
    if (checks.isEmpty()) {
      out.println("No advisory in the database names " + c + ".");
    }
    for (Check ch : checks) {
      String status =
          switch (ch.status()) {
            case AFFECTED -> "AFFECTED";
            case NOT_AFFECTED -> "not affected";
            case WITHDRAWN -> "withdrawn";
          };
      out.println(
          "  "
              + Text.cell(status, 14)
              + Text.cell(ch.advisory().id(), 16)
              + Text.cell(ch.advisory().severity().label(), 9)
              + Text.clean(ch.advisory().title(), 100));
      out.println("  " + " ".repeat(14) + Text.clean(ch.reason(), 600));
      out.println(
          "  "
              + " ".repeat(14)
              + "severity from: "
              + Text.clean(ch.advisory().severitySource(), 200));
    }
    long affected = checks.stream().filter(Check::affected).count();
    out.println();
    if (affected == 0) {
      out.println("Verdict: " + v + " is not affected by any known advisory.");
      return ExitCodes.OK;
    }
    List<String> ids =
        checks.stream().filter(Check::affected).map(ch -> ch.advisory().id()).toList();
    out.println(
        "Verdict: "
            + v
            + " is affected by "
            + affected
            + (affected == 1 ? " advisory (" : " advisories (")
            + String.join(", ", ids)
            + ").");
    UpgradeSuggestion s = UpgradeAdvisor.suggest(db.forPackage(c), c, v);
    String head =
        switch (s.kind()) {
          case SAME_MAJOR -> s.version() + " (same major version)";
          case NEXT_MAJOR -> s.version() + " (next major version)";
          case NONE_KNOWN -> "none known";
          case NOT_NEEDED -> "not needed";
        };
    out.println("Smallest safe upgrade: " + head);
    out.println("  " + Text.clean(s.explanation(), 2000));
    out.flush();
    log.debug("explain finished: " + s.kind().name().toLowerCase(Locale.ROOT));
    return ExitCodes.FINDINGS;
  }
}
