package io.github.arjunpotluri7spec.depwatch.cli;

import io.github.arjunpotluri7spec.depwatch.util.DepwatchException;
import io.github.arjunpotluri7spec.depwatch.version.InvalidVersionException;
import io.github.arjunpotluri7spec.depwatch.version.MavenVersion;
import io.github.arjunpotluri7spec.depwatch.version.VersionRange;
import java.io.PrintWriter;
import java.util.Optional;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;

/** {@code depwatch version compare|in-range}: the version engine on the command line. */
@Command(
    name = "version",
    mixinStandardHelpOptions = true,
    versionProvider = VersionProvider.class,
    description = "Compare Maven versions and test range membership.",
    subcommands = {VersionCommand.Compare.class, VersionCommand.InRange.class})
public final class VersionCommand implements Callable<Integer> {

  @Spec CommandSpec spec;

  @Override
  public Integer call() {
    spec.commandLine().usage(spec.commandLine().getErr());
    return ExitCodes.ERROR;
  }

  static MavenVersion parse(String text) {
    try {
      return MavenVersion.parse(text);
    } catch (InvalidVersionException e) {
      throw new DepwatchException(e.getMessage());
    }
  }

  /** {@code depwatch version compare A B}. */
  @Command(
      name = "compare",
      mixinStandardHelpOptions = true,
      versionProvider = VersionProvider.class,
      description = "Print whether A <, == or > B under Maven ordering, with canonical forms.",
      footer = {"", "Exit codes: 0 = compared, 2 = invalid version."})
  public static final class Compare implements Callable<Integer> {
    @Spec CommandSpec spec;

    @Mixin LoggingOptions logging;

    @Parameters(index = "0", paramLabel = "A")
    String a;

    @Parameters(index = "1", paramLabel = "B")
    String b;

    @Override
    public Integer call() {
      MavenVersion va = parse(a);
      MavenVersion vb = parse(b);
      int c = va.compareTo(vb);
      PrintWriter out = spec.commandLine().getOut();
      out.println(va + " " + (c < 0 ? "<" : c == 0 ? "==" : ">") + " " + vb);
      out.println("  " + va + " -> canonical " + va.canonical());
      out.println("  " + vb + " -> canonical " + vb.canonical());
      out.flush();
      return ExitCodes.OK;
    }
  }

  /** {@code depwatch version in-range V RANGE}. */
  @Command(
      name = "in-range",
      mixinStandardHelpOptions = true,
      versionProvider = VersionProvider.class,
      description = {
        "Test whether version V satisfies a Maven range such as [1.2,2.0), (,1.5], [1.0]",
        "or the union [1,2),[3,4). Quote the range in your shell."
      },
      footer = {"", "Exit codes: 0 = in range, 1 = not in range, 2 = invalid version or range."})
  public static final class InRange implements Callable<Integer> {
    @Spec CommandSpec spec;

    @Mixin LoggingOptions logging;

    @Parameters(index = "0", paramLabel = "V")
    String version;

    @Parameters(index = "1", paramLabel = "RANGE")
    String range;

    @Override
    public Integer call() {
      MavenVersion v = parse(version);
      VersionRange r;
      try {
        r = VersionRange.parse(range);
      } catch (InvalidVersionException e) {
        throw new DepwatchException(e.getMessage());
      }
      PrintWriter out = spec.commandLine().getOut();
      if (r.isSoftRequirement()) {
        out.println(
            v
                + " satisfies "
                + r
                + ": a plain version is a soft requirement (a recommendation), which Maven lets"
                + " any version satisfy. Use ["
                + r
                + "] to require exactly "
                + r
                + ".");
        out.flush();
        return ExitCodes.OK;
      }
      Optional<VersionRange.Restriction> m = r.matchingRestriction(v);
      if (m.isPresent()) {
        out.println(v + " is in " + r + " (matches " + m.get() + ")");
      } else {
        out.println(v + " is not in " + r);
      }
      for (VersionRange.Restriction res : r.restrictions()) {
        if (res.upper() != null && v.isPreRelease() && v.isBefore(res.upper())) {
          String upper = res.upper().toString();
          if (v.canonical().startsWith(res.upper().canonical() + "-")) {
            out.println(
                "  note: "
                    + v
                    + " < "
                    + upper
                    + " because pre-release qualifiers sort before the release, so "
                    + res
                    + " includes it.");
          }
        }
      }
      out.flush();
      return m.isPresent() ? ExitCodes.OK : ExitCodes.FINDINGS;
    }
  }
}
