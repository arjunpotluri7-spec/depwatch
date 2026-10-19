package io.github.arjunpotluri7spec.depwatch.cli;

import io.github.arjunpotluri7spec.depwatch.advisory.AdvisoryDatabase;
import io.github.arjunpotluri7spec.depwatch.config.ConfigLoader;
import io.github.arjunpotluri7spec.depwatch.config.DepwatchConfig;
import io.github.arjunpotluri7spec.depwatch.config.LicenseMap;
import io.github.arjunpotluri7spec.depwatch.input.InputFormat;
import io.github.arjunpotluri7spec.depwatch.model.Diagnostic;
import io.github.arjunpotluri7spec.depwatch.model.Severity;
import io.github.arjunpotluri7spec.depwatch.report.ReportFormat;
import io.github.arjunpotluri7spec.depwatch.scan.ScanResult;
import io.github.arjunpotluri7spec.depwatch.scan.Scanner;
import io.github.arjunpotluri7spec.depwatch.util.DepwatchException;
import io.github.arjunpotluri7spec.depwatch.util.Limits;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;

/** {@code depwatch scan}. */
@Command(
    name = "scan",
    mixinStandardHelpOptions = true,
    versionProvider = VersionProvider.class,
    description = {
      "Audit the dependencies in one or more pom.xml, gradle.lockfile or CycloneDX JSON files.",
      "Each finding says why the version is affected and names the smallest safe upgrade."
    },
    footer = {
      "",
      "Exit codes: 0 = no unsuppressed finding at or above --fail-on; 1 = at least one;",
      "2 = usage/config/input error or a rejected input file (report still written)."
    })
public final class ScanCommand implements Callable<Integer> {

  /** {@code --fail-on} threshold. */
  public enum FailOn {
    NONE,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
  }

  @Spec CommandSpec spec;

  @Mixin LoggingOptions logging;

  @Mixin CommonDbOptions dbOptions;

  @Parameters(paramLabel = "INPUT", arity = "1..*", description = "Files to audit.")
  List<Path> inputs;

  @Option(
      names = "--config",
      paramLabel = "FILE",
      description = "YAML config: license policy, exceptions, suppressions.")
  Path config;

  @Option(
      names = "--licenses",
      paramLabel = "FILE",
      description =
          "YAML map of group:artifact[:version] to SPDX expression, for inputs without"
              + " license data.")
  Path licenses;

  @Option(
      names = "--input-type",
      paramLabel = "TYPE",
      description = "Override detection for all inputs: pom, gradle-lockfile or cyclonedx.")
  String inputType;

  @Option(
      names = "--format",
      paramLabel = "FORMAT",
      defaultValue = "table",
      description = "Report format: table (default), json, sarif or markdown.")
  ReportFormat format;

  @Option(
      names = {"-o", "--output"},
      paramLabel = "FILE",
      description = "Write the report here (mode 0600) instead of stdout.")
  Path output;

  @Option(names = "--force", description = "Overwrite --output if it exists.")
  boolean force;

  @Option(
      names = "--fail-on",
      paramLabel = "SEVERITY",
      defaultValue = "low",
      description =
          "Exit 1 if an unsuppressed finding is at or above: low (default), medium, high,"
              + " critical, or none to never fail on findings. Unknown severity counts as high.")
  FailOn failOn;

  @Option(
      names = "--include-dev",
      description =
          "Also check test-scope / test-configuration / CycloneDX 'excluded' dependencies.")
  boolean includeDev;

  @Override
  public Integer call() {
    CliLogger log = logging.logger(spec.commandLine().getErr());
    Optional<InputFormat> forced = Optional.empty();
    if (inputType != null) {
      forced = InputFormat.fromId(inputType);
      if (forced.isEmpty()) {
        throw new DepwatchException(
            "--input-type must be pom, gradle-lockfile or cyclonedx (got '" + inputType + "')");
      }
    }
    if (output != null && !force && java.nio.file.Files.exists(output)) {
      throw new DepwatchException(output + ": file exists (use --force to overwrite)");
    }
    Limits limits = dbOptions.limits();
    DepwatchConfig cfg =
        config == null ? DepwatchConfig.empty() : ConfigLoader.load(config, limits);
    LicenseMap map = licenses == null ? null : ConfigLoader.loadLicenseMap(licenses, limits);
    if (map != null && cfg.licensePolicy().isEmpty()) {
      log.warn("--licenses given but the config has no licenses section; no license checks run");
    }
    AdvisoryDatabase db = dbOptions.load(log);

    ScanResult result =
        Scanner.scan(
            new Scanner.Request(
                inputs, forced, db, cfg, map, includeDev, limits, VersionProvider.version()));
    int dbDiagnostics = db.diagnostics().size();
    List<Diagnostic> diags = result.diagnostics();
    diags.subList(Math.min(dbDiagnostics, diags.size()), diags.size()).forEach(log::diagnostic);

    OutputWriter.write(format.render(result), output, force, spec.commandLine().getOut());
    if (output != null) {
      log.info("report written to " + output);
    }
    if (result.failedInputs() > 0) {
      log.error(
          result.failedInputs()
              + " input file(s) were rejected; exiting with 2 so the gap is not missed");
      return ExitCodes.ERROR;
    }
    if (failOn != FailOn.NONE && result.failsAt(Severity.valueOf(failOn.name()))) {
      return ExitCodes.FINDINGS;
    }
    return ExitCodes.OK;
  }
}
