package io.github.arjunpotluri7spec.depwatch.report;

import io.github.arjunpotluri7spec.depwatch.advisory.AdvisoryDatabase;
import io.github.arjunpotluri7spec.depwatch.model.Severity;
import io.github.arjunpotluri7spec.depwatch.scan.Finding;
import io.github.arjunpotluri7spec.depwatch.scan.ScanResult;
import io.github.arjunpotluri7spec.depwatch.util.Text;

/** Human-readable terminal report. */
public final class TableReport {

  private TableReport() {}

  public static String render(ScanResult r) {
    StringBuilder b = new StringBuilder();
    b.append("Depwatch ").append(r.toolVersion()).append(" - offline dependency audit\n");
    AdvisoryDatabase.Stats db = r.database();
    b.append("Advisory DB: ")
        .append(db.location())
        .append(" (")
        .append(db.recordsLoaded())
        .append(" Maven advisories, ")
        .append(db.withdrawn())
        .append(" withdrawn, ")
        .append(db.recordsSkipped())
        .append(" skipped)\n");
    for (ScanResult.InputSummary in : r.inputs()) {
      b.append("Input: ").append(in.file());
      if (in.error() != null) {
        b.append(" (rejected: see diagnostics)\n");
        continue;
      }
      b.append(" [").append(in.format().id()).append("] ").append(in.checked()).append(" checked");
      if (in.devSkipped() > 0) {
        b.append(", ").append(in.devSkipped()).append(" dev skipped (use --include-dev)");
      }
      if (in.unusable() > 0) {
        b.append(", ").append(in.unusable()).append(" unresolved");
      }
      b.append('\n');
    }
    b.append('\n');
    if (r.findings().isEmpty()) {
      b.append("No findings.\n");
    } else {
      int pkgW = 8;
      for (Finding f : r.findings()) {
        pkgW = Math.max(pkgW, f.dependency().coordinate().toString().length());
      }
      pkgW = Math.min(pkgW, 40);
      String header =
          Text.cell("SEVERITY", 9)
              + "  "
              + Text.cell("PACKAGE", pkgW)
              + "  "
              + Text.cell("VERSION", 10)
              + "  "
              + Text.cell("FINDING", 16)
              + "  "
              + "FIX / NOTE";
      b.append(header).append('\n');
      for (Finding f : r.findings()) {
        String sev = f.severity().label().toUpperCase(java.util.Locale.ROOT);
        String fix;
        if (f.suppressed()) {
          fix = "suppressed";
        } else if (f.fix() != null) {
          fix = f.fix().shortText();
        } else {
          fix = "";
        }
        b.append(Text.cell(sev, 9))
            .append("  ")
            .append(Text.cell(f.dependency().coordinate().toString(), pkgW))
            .append("  ")
            .append(Text.cell(f.dependency().version().toString(), 10))
            .append("  ")
            .append(Text.cell(f.ruleId(), 16))
            .append("  ")
            .append(fix)
            .append('\n');
      }
      b.append("\nDetails\n");
      for (Finding f : r.findings()) {
        b.append("\n[")
            .append(f.severity().label().toUpperCase(java.util.Locale.ROOT))
            .append("] ")
            .append(f.ruleId())
            .append("  ")
            .append(f.dependency().gav())
            .append("  (")
            .append(f.dependency().location())
            .append(")\n");
        b.append("  ").append(Text.clean(f.title(), 200)).append('\n');
        b.append("  why: ").append(Text.clean(f.why())).append('\n');
        if (f.advisory() != null) {
          b.append("  severity: ").append(Text.clean(f.advisory().severitySource())).append('\n');
          if (!f.advisory().aliases().isEmpty()) {
            b.append("  aliases: ")
                .append(Text.clean(String.join(", ", f.advisory().aliases())))
                .append('\n');
          }
        }
        if (f.fix() != null) {
          b.append("  fix: ").append(Text.clean(f.fix().explanation(), 800)).append('\n');
        }
        if (f.suppressed()) {
          b.append("  suppressed: ").append(Text.clean(f.suppressedReason())).append('\n');
        }
      }
    }
    b.append('\n').append(summaryLine(r)).append('\n');
    return b.toString();
  }

  static String summaryLine(ScanResult r) {
    StringBuilder b = new StringBuilder("Summary: ");
    b.append(r.checkedDependencies()).append(" dependencies checked, ");
    b.append(r.activeFindings()).append(r.activeFindings() == 1 ? " finding" : " findings");
    StringBuilder parts = new StringBuilder();
    for (Severity s :
        new Severity[] {
          Severity.CRITICAL, Severity.HIGH, Severity.UNKNOWN, Severity.MEDIUM, Severity.LOW
        }) {
      long n = r.count(s);
      if (n > 0) {
        if (parts.length() > 0) {
          parts.append(", ");
        }
        parts.append(n).append(' ').append(s.label());
      }
    }
    if (parts.length() > 0) {
      b.append(" (").append(parts).append(')');
    }
    long suppressed = r.findings().size() - r.activeFindings();
    if (suppressed > 0) {
      b.append(", ").append(suppressed).append(" suppressed");
    }
    if (r.failedInputs() > 0) {
      b.append(", ").append(r.failedInputs()).append(" input(s) rejected");
    }
    return b.toString();
  }
}
