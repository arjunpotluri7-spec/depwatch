package io.github.arjunpotluri7spec.depwatch.report;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.arjunpotluri7spec.depwatch.model.Severity;
import io.github.arjunpotluri7spec.depwatch.scan.Finding;
import io.github.arjunpotluri7spec.depwatch.scan.ScanResult;
import io.github.arjunpotluri7spec.depwatch.util.Json;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * SARIF 2.1.0 output (OASIS SARIF v2.1.0). One rule per advisory or license rule, one result per
 * finding. Locations point at the input file and, where known, the line of the {@code <artifactId>}
 * (POM), the lockfile entry, or the component's purl (SBOM).
 */
public final class SarifReport {

  public static final String SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json";
  public static final String INFO_URI = "https://github.com/arjunpotluri7-spec/depwatch";
  private static final JsonNodeFactory F = JsonNodeFactory.instance;

  private SarifReport() {}

  public static String render(ScanResult r) {
    try {
      return Json.mapper().writeValueAsString(tree(r)) + "\n";
    } catch (JsonProcessingException e) {
      throw new UncheckedIOException(e);
    }
  }

  /**
   * {@code error} for critical, high and unknown; {@code warning} for medium; else {@code note}.
   */
  public static String level(Severity s) {
    return switch (s) {
      case CRITICAL, HIGH, UNKNOWN -> "error";
      case MEDIUM -> "warning";
      case LOW -> "note";
    };
  }

  public static ObjectNode tree(ScanResult r) {
    ObjectNode root = F.objectNode();
    root.put("$schema", SCHEMA_URI);
    root.put("version", "2.1.0");
    ObjectNode run = root.putArray("runs").addObject();
    ObjectNode driver = run.putObject("tool").putObject("driver");
    driver.put("name", "depwatch");
    driver.put("version", r.toolVersion());
    driver.put("informationUri", INFO_URI);
    ArrayNode rules = driver.putArray("rules");

    Map<String, Integer> ruleIndex = new LinkedHashMap<>();
    for (Finding f : r.findings()) {
      if (ruleIndex.containsKey(f.ruleId())) {
        continue;
      }
      ruleIndex.put(f.ruleId(), ruleIndex.size());
      ObjectNode rule = rules.addObject();
      rule.put("id", f.ruleId());
      rule.put("name", ruleName(f));
      rule.putObject("shortDescription").put("text", shortDescription(f));
      if (f.advisory() != null && !f.advisory().details().isBlank()) {
        rule.putObject("fullDescription").put("text", f.advisory().details().strip());
      }
      if (f.advisory() != null && !f.advisory().references().isEmpty()) {
        rule.put("helpUri", f.advisory().references().get(0).url());
      }
      rule.putObject("defaultConfiguration").put("level", level(f.severity()));
      ObjectNode props = rule.putObject("properties");
      ArrayNode tags = props.putArray("tags");
      tags.add(f.type() == Finding.Type.VULNERABILITY ? "security" : "license");
      tags.add(f.type() == Finding.Type.VULNERABILITY ? "vulnerability" : "compliance");
      props.put("severity", f.severity().label());
    }

    ObjectNode original = run.putObject("originalUriBaseIds");
    original.putObject("SRCROOT").put("uri", "./");
    ArrayNode results = run.putArray("results");
    for (Finding f : r.findings()) {
      ObjectNode res = results.addObject();
      res.put("ruleId", f.ruleId());
      res.put("ruleIndex", ruleIndex.get(f.ruleId()));
      res.put("level", level(f.severity()));
      res.putObject("message").put("text", message(f));
      ObjectNode phys = res.putArray("locations").addObject().putObject("physicalLocation");
      ObjectNode art = phys.putObject("artifactLocation");
      art.put("uri", uri(f.dependency().location().file()));
      if (!isAbsolute(f.dependency().location().file())) {
        art.put("uriBaseId", "SRCROOT");
      }
      if (f.dependency().location().line() > 0) {
        phys.putObject("region").put("startLine", f.dependency().location().line());
      }
      res.putObject("partialFingerprints").put("depwatchFinding/v1", fingerprint(f));
      if (f.suppressed()) {
        ObjectNode sup = res.putArray("suppressions").addObject();
        sup.put("kind", "external");
        sup.put("justification", f.suppressedReason());
      }
      ObjectNode props = res.putObject("properties");
      props.put("package", f.dependency().coordinate().toString());
      props.put("version", f.dependency().version().toString());
      props.put("severity", f.severity().label());
      if (f.fix() != null) {
        props.put(
            "fixKind", f.fix().kind().name().toLowerCase(java.util.Locale.ROOT).replace('_', '-'));
        f.fix().target().ifPresent(v -> props.put("fixVersion", v.toString()));
      }
    }
    return root;
  }

  private static String ruleName(Finding f) {
    return switch (f.ruleId()) {
      case Finding.LICENSE_DENIED -> "LicenseDenied";
      case Finding.LICENSE_UNKNOWN -> "LicenseUnknown";
      case Finding.LICENSE_REVIEW -> "LicenseReviewRequired";
      default -> "VulnerableDependency";
    };
  }

  private static String shortDescription(Finding f) {
    if (f.advisory() != null) {
      return f.advisory().title().isBlank() ? f.ruleId() : f.advisory().title();
    }
    return switch (f.ruleId()) {
      case Finding.LICENSE_DENIED -> "Dependency license is denied by the license policy";
      case Finding.LICENSE_REVIEW -> "Dependency license requires review";
      default -> "Dependency license is unknown or not covered by the license policy";
    };
  }

  private static String message(Finding f) {
    StringBuilder b = new StringBuilder();
    b.append(f.dependency().gav()).append(": ").append(f.title()).append(". ").append(f.why());
    if (!b.toString().endsWith(".")) {
      b.append('.');
    }
    if (f.fix() != null) {
      b.append(' ').append(f.fix().explanation());
    }
    return b.toString();
  }

  static boolean isAbsolute(String file) {
    return file.startsWith("/") || (file.length() > 2 && file.charAt(1) == ':');
  }

  /** A relative URI reference with forward slashes and unsafe characters percent-encoded. */
  static String uri(String file) {
    String p = file.replace('\\', '/');
    if (p.startsWith("./")) {
      p = p.substring(2);
    }
    StringBuilder b = new StringBuilder();
    if (isAbsolute(p)) {
      b.append(p.startsWith("/") ? "file://" : "file:///");
    }
    for (byte by : p.getBytes(StandardCharsets.UTF_8)) {
      int c = by & 0xFF;
      if ((c >= 'a' && c <= 'z')
          || (c >= 'A' && c <= 'Z')
          || (c >= '0' && c <= '9')
          || "-._~/:".indexOf(c) >= 0) {
        b.append((char) c);
      } else {
        b.append('%').append(String.format("%02X", c));
      }
    }
    return b.toString();
  }

  private static String fingerprint(Finding f) {
    String key =
        f.ruleId()
            + "|"
            + f.dependency().coordinate()
            + "|"
            + f.dependency().version()
            + "|"
            + f.dependency().location().file();
    try {
      byte[] h = MessageDigest.getInstance("SHA-256").digest(key.getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(h, 0, 16);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 is not available", e);
    }
  }
}
