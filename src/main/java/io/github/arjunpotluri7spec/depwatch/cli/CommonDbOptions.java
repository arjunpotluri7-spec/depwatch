package io.github.arjunpotluri7spec.depwatch.cli;

import io.github.arjunpotluri7spec.depwatch.advisory.AdvisoryDatabase;
import io.github.arjunpotluri7spec.depwatch.advisory.OsvLoader;
import io.github.arjunpotluri7spec.depwatch.util.DepwatchException;
import io.github.arjunpotluri7spec.depwatch.util.Limits;
import java.nio.file.Path;
import picocli.CommandLine.Option;

/** Options for locating and bounding the advisory database. */
public final class CommonDbOptions {

  @Option(
      names = "--db",
      paramLabel = "DIR",
      required = true,
      description = "Directory of OSV advisory JSON files (searched recursively).")
  Path db;

  @Option(
      names = "--max-file-size",
      paramLabel = "MIB",
      defaultValue = "32",
      description =
          "Largest file read, in MiB (inputs, config, each DB file). Default: ${DEFAULT-VALUE}.")
  int maxFileMib;

  @Option(
      names = "--follow-symlinks",
      description = "Follow symbolic links inside the --db directory (off by default).")
  boolean followSymlinks;

  Limits limits() {
    if (maxFileMib < 1 || maxFileMib > 4096) {
      throw new DepwatchException("--max-file-size must be between 1 and 4096 MiB");
    }
    return new Limits(maxFileMib * 1024L * 1024L, Limits.DEFAULT_MAX_DB_FILES, followSymlinks);
  }

  AdvisoryDatabase load(CliLogger log) {
    AdvisoryDatabase database = OsvLoader.load(db, limits());
    database.diagnostics().forEach(log::diagnostic);
    log.info(
        "loaded "
            + database.stats().recordsLoaded()
            + " Maven advisories from "
            + database.stats().filesRead()
            + " files in "
            + db);
    return database;
  }
}
