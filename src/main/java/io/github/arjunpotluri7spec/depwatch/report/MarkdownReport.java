package io.github.arjunpotluri7spec.depwatch.report;

import io.github.arjunpotluri7spec.depwatch.model.Diagnostic;
import io.github.arjunpotluri7spec.depwatch.scan.Finding;
import io.github.arjunpotluri7spec.depwatch.scan.ScanResult;
import io.github.arjunpotluri7spec.depwatch.util.Text;
import java.util.Locale;

/** Markdown report, suitable for a pull request comment or a ticket. */
public final class MarkdownReport {

  private MarkdownReport() {}

  public static String render(ScanResult r) {
    StringBuilder b = new StringBuilder();
    b.append("# Depwatch report\n\n");
    b.append("Depwatch ")
        .append(r.toolVersion())
        .append(", advisory database ")
        .append(code(r.database().location()))
        .append(" (")
        .append(r.database().recordsLoaded())
        .append(" Maven advisories).\n\n");
    b.append("| Input | Format | Checked | Dev skipped | Unresolved |\n");
    b.append("|---|---|---:|---:|---:|\n");
    for (ScanResult.InputSummary in : r.inputs()) {
      b.append("| ")
          .append(code(in.file()))
          .append(" | ")
          .append(in.error() != null ? "rejected" : in.format().id())
          .append(" | ")
          .append(in.checked())
          .append(" | ")
          .append(in.devSkipped())
          .append(" | ")
          .append(in.unusable())
          .append(" |\n");
    }
    b.append("\n**")
        .append(md(TableReport.summaryLine(r).substring("Summary: ".length())))
        .append("**\n\n");
    if (!r.findings().isEmpty()) {
      b.append("## Findings\n\n");
      b.append("| Severity | Package | Version | Finding | Fix |\n");
      b.append("|---|---|---|---|---|\n");
      for (Finding f : r.findings()) {
        b.append("| ")
            .append(f.severity().label())
            .append(" | ")
            .append(code(f.dependency().coordinate().toString()))
            .append(" | ")
            .append(md(f.dependency().version().toString()))
            .append(" | ")
            .append(md(f.ruleId()))
            .append(" | ")
            .append(f.suppressed() ? "suppressed" : f.fix() == null ? "" : md(f.fix().shortText()))
            .append(" |\n");
      }
      b.append("\n## Details\n");
      for (Finding f : r.findings()) {
        b.append("\n### ")
            .append(md(f.ruleId()))
            .append(": ")
            .append(code(f.dependency().gav()))
            .append("\n\n");
        b.append("- **Severity:** ").append(f.severity().label()).append('\n');
        b.append("- **Location:** ")
            .append(code(f.dependency().location().toString()))
            .append('\n');
        b.append("- **Summary:** ").append(md(Text.clean(f.title(), 300))).append('\n');
        b.append("- **Why:** ").append(md(Text.clean(f.why()))).append('\n');
        if (f.fix() != null) {
          b.append("- **Fix:** ").append(md(Text.clean(f.fix().explanation(), 800))).append('\n');
        }
        if (f.suppressed()) {
          b.append("- **Suppressed:** ").append(md(Text.clean(f.suppressedReason()))).append('\n');
        }
      }
    }
    long warnings =
        r.diagnostics().stream().filter(d -> d.level() != Diagnostic.Level.INFO).count();
    if (warnings > 0) {
      b.append("\n## Diagnostics\n\n");
      for (Diagnostic d : r.diagnostics()) {
        if (d.level() == Diagnostic.Level.INFO) {
          continue;
        }
        b.append("- ")
            .append(d.level().name().toLowerCase(Locale.ROOT))
            .append(": ")
            .append(md(Text.clean(d.render())))
            .append('\n');
      }
    }
    return b.toString();
  }

  /** An inline code span; backticks and pipes inside are replaced so the span cannot break. */
  static String code(String s) {
    return "`" + Text.clean(s, 2000).replace('`', '\'').replace("|", "\\|") + "`";
  }

  /** Escapes characters that would change Markdown or HTML structure. */
  static String md(String s) {
    StringBuilder b = new StringBuilder();
    for (char c : Text.clean(s, 2000).toCharArray()) {
      switch (c) {
        case '|', '`', '*', '_', '[', ']', '<', '>', '#', '\\' -> b.append('\\').append(c);
        default -> b.append(c);
      }
    }
    return b.toString();
  }
}
