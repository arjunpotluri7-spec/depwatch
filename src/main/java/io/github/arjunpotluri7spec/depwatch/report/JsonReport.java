package io.github.arjunpotluri7spec.depwatch.report;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.arjunpotluri7spec.depwatch.advisory.Advisory;
import io.github.arjunpotluri7spec.depwatch.advisory.AdvisoryDatabase;
import io.github.arjunpotluri7spec.depwatch.advisory.Reference;
import io.github.arjunpotluri7spec.depwatch.match.UpgradeSuggestion;
import io.github.arjunpotluri7spec.depwatch.model.Diagnostic;
import io.github.arjunpotluri7spec.depwatch.model.Severity;
import io.github.arjunpotluri7spec.depwatch.scan.Finding;
import io.github.arjunpotluri7spec.depwatch.scan.ScanResult;
import io.github.arjunpotluri7spec.depwatch.util.Json;
import java.io.UncheckedIOException;
import java.util.Locale;

/**
 * Stable JSON report, schema {@value #SCHEMA}. Fields are only ever added within a schema version;
 * see {@code docs/json-schema.md}.
 */
public final class JsonReport {

  public static final String SCHEMA = "depwatch-report/1";
  private static final JsonNodeFactory F = JsonNodeFactory.instance;

  private JsonReport() {}

  public static String render(ScanResult r) {
    try {
      return Json.mapper().writeValueAsString(tree(r)) + "\n";
    } catch (JsonProcessingException e) {
      throw new UncheckedIOException(e);
    }
  }

  public static ObjectNode tree(ScanResult r) {
    ObjectNode root = F.objectNode();
    root.put("schema", SCHEMA);
    ObjectNode tool = root.putObject("tool");
    tool.put("name", "depwatch");
    tool.put("version", r.toolVersion());

    AdvisoryDatabase.Stats s = r.database();
    ObjectNode db = root.putObject("database");
    db.put("location", s.location());
    db.put("advisories", s.recordsLoaded());
    db.put("withdrawn", s.withdrawn());
    db.put("skipped", s.recordsSkipped());

    ArrayNode inputs = root.putArray("inputs");
    for (ScanResult.InputSummary in : r.inputs()) {
      ObjectNode o = inputs.addObject();
      o.put("file", in.file());
      o.put("format", in.format() == null ? null : in.format().id());
      o.put("dependencies", in.dependencies());
      o.put("checked", in.checked());
      o.put("devSkipped", in.devSkipped());
      o.put("unresolved", in.unusable());
      o.put("error", in.error());
    }

    ObjectNode summary = root.putObject("summary");
    summary.put("dependenciesChecked", r.checkedDependencies());
    summary.put("findings", r.activeFindings());
    summary.put("suppressed", r.findings().size() - r.activeFindings());
    ObjectNode bySev = summary.putObject("bySeverity");
    for (Severity sev :
        new Severity[] {
          Severity.CRITICAL, Severity.HIGH, Severity.UNKNOWN, Severity.MEDIUM, Severity.LOW
        }) {
      bySev.put(sev.label(), r.count(sev));
    }
    summary.put("licenseChecks", r.licenseChecks());
    summary.put("includeDev", r.includeDev());
    summary.put("rejectedInputs", r.failedInputs());

    ArrayNode findings = root.putArray("findings");
    for (Finding f : r.findings()) {
      findings.add(finding(f));
    }
    ArrayNode diags = root.putArray("diagnostics");
    for (Diagnostic d : r.diagnostics()) {
      ObjectNode o = diags.addObject();
      o.put("level", d.level().name().toLowerCase(Locale.ROOT));
      o.put("file", d.file());
      if (d.line() > 0) {
        o.put("line", d.line());
      } else {
        o.putNull("line");
      }
      o.put("message", d.message());
    }
    return root;
  }

  static ObjectNode finding(Finding f) {
    ObjectNode o = F.objectNode();
    o.put("type", f.type().name().toLowerCase(Locale.ROOT));
    o.put("ruleId", f.ruleId());
    o.put("severity", f.severity().label());
    o.put("package", f.dependency().coordinate().toString());
    o.put("version", f.dependency().version().toString());
    o.put("scope", f.dependency().scope());
    o.put("origin", f.dependency().origin());
    ObjectNode loc = o.putObject("location");
    loc.put("file", f.dependency().location().file());
    if (f.dependency().location().line() > 0) {
      loc.put("line", f.dependency().location().line());
    } else {
      loc.putNull("line");
    }
    o.put("title", f.title());
    o.put("why", f.why());
    Advisory a = f.advisory();
    if (a != null) {
      ObjectNode adv = o.putObject("advisory");
      adv.put("id", a.id());
      ArrayNode aliases = adv.putArray("aliases");
      a.aliases().forEach(aliases::add);
      adv.put("summary", a.summary());
      adv.put("severitySource", a.severitySource());
      adv.put("matchedRange", f.matchedRange());
      adv.put("modified", a.modified());
      adv.put("source", a.sourceFile());
      ArrayNode refs = adv.putArray("references");
      for (Reference ref : a.references()) {
        ObjectNode rn = refs.addObject();
        rn.put("type", ref.type());
        rn.put("url", ref.url());
      }
    } else {
      o.putNull("advisory");
    }
    UpgradeSuggestion fix = f.fix();
    if (fix != null) {
      ObjectNode fn = o.putObject("fix");
      fn.put("kind", fix.kind().name().toLowerCase(Locale.ROOT).replace('_', '-'));
      fn.put("version", fix.target().map(Object::toString).orElse(null));
      fn.put("explanation", fix.explanation());
    } else {
      o.putNull("fix");
    }
    if (f.license() != null) {
      ObjectNode ln = o.putObject("license");
      ln.put("status", f.license().status().name().toLowerCase(Locale.ROOT));
      ln.put("expression", f.license().expression());
      ln.put("explanation", f.license().explanation());
    } else {
      o.putNull("license");
    }
    o.put("suppressed", f.suppressed());
    o.put("suppressionReason", f.suppressedReason());
    return o;
  }
}
