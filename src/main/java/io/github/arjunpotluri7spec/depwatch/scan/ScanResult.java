package io.github.arjunpotluri7spec.depwatch.scan;

import io.github.arjunpotluri7spec.depwatch.advisory.AdvisoryDatabase;
import io.github.arjunpotluri7spec.depwatch.input.InputFormat;
import io.github.arjunpotluri7spec.depwatch.model.Diagnostic;
import io.github.arjunpotluri7spec.depwatch.model.Severity;
import java.util.List;

/**
 * Everything a report needs.
 *
 * @param inputs one entry per input file, including files that failed
 * @param findings sorted with {@link Finding#ORDER}
 * @param diagnostics problems from the database, inputs and configuration
 * @param licenseChecks whether license policy checks ran
 */
public record ScanResult(
    String toolVersion,
    List<InputSummary> inputs,
    List<Finding> findings,
    List<Diagnostic> diagnostics,
    AdvisoryDatabase.Stats database,
    boolean licenseChecks,
    boolean includeDev) {

  /**
   * @param format null when the file could not be read at all
   * @param error the reason the file was rejected, or null
   */
  public record InputSummary(
      String file,
      InputFormat format,
      int dependencies,
      int checked,
      int devSkipped,
      int unusable,
      String error) {}

  public ScanResult {
    inputs = List.copyOf(inputs);
    findings = List.copyOf(findings);
    diagnostics = List.copyOf(diagnostics);
  }

  public int checkedDependencies() {
    return inputs.stream().mapToInt(InputSummary::checked).sum();
  }

  public int failedInputs() {
    return (int) inputs.stream().filter(i -> i.error() != null).count();
  }

  public long count(Severity s) {
    return findings.stream().filter(f -> !f.suppressed() && f.severity() == s).count();
  }

  public long activeFindings() {
    return findings.stream().filter(f -> !f.suppressed()).count();
  }

  /** True if any unsuppressed finding is at or above the threshold. */
  public boolean failsAt(Severity threshold) {
    return findings.stream().anyMatch(f -> !f.suppressed() && f.severity().atLeast(threshold));
  }
}
