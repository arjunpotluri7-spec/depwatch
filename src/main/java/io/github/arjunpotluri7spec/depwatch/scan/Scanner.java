package io.github.arjunpotluri7spec.depwatch.scan;

import io.github.arjunpotluri7spec.depwatch.advisory.Advisory;
import io.github.arjunpotluri7spec.depwatch.advisory.AdvisoryDatabase;
import io.github.arjunpotluri7spec.depwatch.config.DepwatchConfig;
import io.github.arjunpotluri7spec.depwatch.config.LicenseMap;
import io.github.arjunpotluri7spec.depwatch.config.Suppression;
import io.github.arjunpotluri7spec.depwatch.input.InputFormat;
import io.github.arjunpotluri7spec.depwatch.input.InputReader;
import io.github.arjunpotluri7spec.depwatch.input.ParsedInput;
import io.github.arjunpotluri7spec.depwatch.license.LicensePolicy;
import io.github.arjunpotluri7spec.depwatch.license.LicenseVerdict;
import io.github.arjunpotluri7spec.depwatch.match.AdvisoryMatcher;
import io.github.arjunpotluri7spec.depwatch.match.Check;
import io.github.arjunpotluri7spec.depwatch.match.UpgradeAdvisor;
import io.github.arjunpotluri7spec.depwatch.match.UpgradeSuggestion;
import io.github.arjunpotluri7spec.depwatch.model.Dependency;
import io.github.arjunpotluri7spec.depwatch.model.Diagnostic;
import io.github.arjunpotluri7spec.depwatch.model.Severity;
import io.github.arjunpotluri7spec.depwatch.util.DepwatchException;
import io.github.arjunpotluri7spec.depwatch.util.Limits;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/** Runs a scan: read inputs, match advisories, apply the license policy. */
public final class Scanner {

  /**
   * @param licenseMap licenses for inputs without license data; may be null
   */
  public record Request(
      List<Path> inputs,
      Optional<InputFormat> forcedFormat,
      AdvisoryDatabase database,
      DepwatchConfig config,
      LicenseMap licenseMap,
      boolean includeDev,
      Limits limits,
      String toolVersion) {}

  private Scanner() {}

  public static ScanResult scan(Request req) {
    List<Diagnostic> diags = new ArrayList<>(req.database().diagnostics());
    List<ScanResult.InputSummary> summaries = new ArrayList<>();
    List<Finding> findings = new ArrayList<>();
    Optional<LicensePolicy> policy = req.config().licensePolicy();
    boolean anyLicenseCheck = false;

    for (Path p : req.inputs()) {
      ParsedInput in;
      try {
        in = InputReader.read(p, req.forcedFormat(), req.limits());
      } catch (DepwatchException e) {
        diags.add(Diagnostic.error(null, e.getMessage()));
        summaries.add(new ScanResult.InputSummary(p.toString(), null, 0, 0, 0, 0, e.getMessage()));
        continue;
      }
      diags.addAll(in.diagnostics());
      boolean licenseData = in.hasLicenseData() || req.licenseMap() != null;
      int checked = 0;
      int devSkipped = 0;
      for (Dependency raw : in.dependencies()) {
        if (raw.dev() && !req.includeDev()) {
          devSkipped++;
          continue;
        }
        checked++;
        Dependency d = raw;
        if (d.license() == null && req.licenseMap() != null) {
          d = req.licenseMap().lookup(d).map(d::withLicense).orElse(d);
        }
        findings.addAll(vulnerabilities(d, req));
        if (policy.isPresent() && licenseData) {
          anyLicenseCheck = true;
          license(d, policy.get()).ifPresent(findings::add);
        }
      }
      summaries.add(
          new ScanResult.InputSummary(
              in.file(),
              in.format(),
              in.dependencies().size(),
              checked,
              devSkipped,
              in.unusable(),
              null));
    }
    if (policy.isPresent() && !anyLicenseCheck) {
      diags.add(
          Diagnostic.info(
              null,
              "license policy not applied: no input carries license data (use a CycloneDX SBOM"
                  + " or --licenses FILE)"));
    }
    findings.sort(Finding.ORDER);
    return new ScanResult(
        req.toolVersion(),
        summaries,
        findings,
        diags,
        req.database().stats(),
        anyLicenseCheck,
        req.includeDev());
  }

  private static List<Finding> vulnerabilities(Dependency d, Request req) {
    List<Advisory> all = req.database().forPackage(d.coordinate());
    if (all.isEmpty()) {
      return List.of();
    }
    List<Finding> out = new ArrayList<>();
    UpgradeSuggestion fix = null;
    for (Advisory a : all) {
      Check c = AdvisoryMatcher.check(a, d.coordinate(), d.version());
      if (!c.affected()) {
        continue;
      }
      if (fix == null) {
        fix = UpgradeAdvisor.suggest(all, d.coordinate(), d.version());
      }
      String suppressed = null;
      for (Suppression s : req.config().suppressions()) {
        if (s.matches(a.id(), d.coordinate())) {
          suppressed = s.reason();
          break;
        }
      }
      out.add(
          new Finding(
              Finding.Type.VULNERABILITY,
              a.id(),
              a.severity(),
              d,
              a.title(),
              c.reason(),
              c.matchedRange(),
              a,
              fix,
              null,
              suppressed));
    }
    return out;
  }

  private static Optional<Finding> license(Dependency d, LicensePolicy policy) {
    LicenseVerdict v = policy.evaluate(d.coordinate(), d.license());
    if (!v.isFinding()) {
      return Optional.empty();
    }
    String rule;
    Severity sev;
    String title;
    switch (v.status()) {
      case DENIED -> {
        rule = Finding.LICENSE_DENIED;
        sev = Severity.HIGH;
        title = "License denied by policy: " + v.expression();
      }
      case REVIEW -> {
        rule = Finding.LICENSE_REVIEW;
        sev = Severity.LOW;
        title = "License requires review: " + v.expression();
      }
      default -> {
        rule = Finding.LICENSE_UNKNOWN;
        sev = Severity.MEDIUM;
        title =
            v.expression() == null
                ? "No license information"
                : "License not covered by policy: " + v.expression();
      }
    }
    return Optional.of(
        new Finding(
            Finding.Type.LICENSE, rule, sev, d, title, v.explanation(), "", null, null, v, null));
  }
}
