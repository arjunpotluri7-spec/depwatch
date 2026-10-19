package io.github.arjunpotluri7spec.depwatch.report;

import io.github.arjunpotluri7spec.depwatch.scan.ScanResult;

/** Output formats for {@code depwatch scan}. */
public enum ReportFormat {
  TABLE,
  JSON,
  SARIF,
  MARKDOWN;

  public String render(ScanResult r) {
    return switch (this) {
      case TABLE -> TableReport.render(r);
      case JSON -> JsonReport.render(r);
      case SARIF -> SarifReport.render(r);
      case MARKDOWN -> MarkdownReport.render(r);
    };
  }
}
