package io.github.arjunpotluri7spec.depwatch.input;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.arjunpotluri7spec.depwatch.model.Coordinate;
import io.github.arjunpotluri7spec.depwatch.model.Dependency;
import io.github.arjunpotluri7spec.depwatch.model.Diagnostic;
import io.github.arjunpotluri7spec.depwatch.model.SourceLocation;
import io.github.arjunpotluri7spec.depwatch.util.DepwatchException;
import io.github.arjunpotluri7spec.depwatch.util.Json;
import io.github.arjunpotluri7spec.depwatch.version.MavenVersion;
import java.util.ArrayList;
import java.util.List;

/**
 * Reads Maven components from a CycloneDX JSON SBOM (spec 1.4 to 1.6 field names).
 *
 * <p>Components are identified by their {@code purl} ({@code pkg:maven/group/artifact@version});
 * other package types are counted and skipped. Nested {@code components} are included; {@code
 * metadata.component} (the application itself) is not. {@code scope: excluded} marks a
 * development-only component.
 *
 * <p>Licenses: an {@code expression} entry is used as is. Several {@code license} entries are
 * combined with AND, the conservative reading; write an expression such as {@code MIT OR
 * Apache-2.0} for a choice of licenses. A license given only by name is used as a {@code
 * LicenseRef-} identifier, which a policy treats as unknown unless it lists it.
 *
 * <p>Line numbers are best effort: the line where the component's purl text appears.
 */
public final class CycloneDxParser {

  private static final int MAX_COMPONENT_DEPTH = 16;

  private CycloneDxParser() {}

  public static ParsedInput parse(String text, String file) {
    JsonNode root = Json.parse(text, file);
    if (!root.isObject() || !"CycloneDX".equals(root.path("bomFormat").asText())) {
      throw new DepwatchException(file + ": not a CycloneDX JSON document (bomFormat is missing)");
    }
    State st = new State(text, file);
    JsonNode components = root.get("components");
    if (components != null && !components.isNull()) {
      if (!components.isArray()) {
        throw new DepwatchException(file + ": 'components' must be an array");
      }
      walk(components, st, 0);
    }
    return new ParsedInput(file, InputFormat.CYCLONEDX_JSON, st.out, st.diags, st.unusable, true);
  }

  private static final class State {
    final String text;
    final String file;
    final List<Dependency> out = new ArrayList<>();
    final List<Diagnostic> diags = new ArrayList<>();
    int unusable;
    int searchFrom;
    int countedTo;
    int countedLine = 1;
    int nonMaven;

    State(String text, String file) {
      this.text = text;
      this.file = file;
    }
  }

  private static void walk(JsonNode components, State st, int depth) {
    if (depth > MAX_COMPONENT_DEPTH) {
      st.diags.add(Diagnostic.warn(st.file, "components nested too deeply; rest ignored"));
      return;
    }
    for (JsonNode c : components) {
      if (!c.isObject()) {
        st.unusable++;
        st.diags.add(Diagnostic.warn(st.file, "component that is not an object skipped"));
        continue;
      }
      component(c, st);
      JsonNode nested = c.get("components");
      if (nested != null && nested.isArray()) {
        walk(nested, st, depth + 1);
      }
    }
  }

  private static void component(JsonNode c, State st) {
    String purl = c.path("purl").asText("");
    String label = c.path("name").asText("?");
    if (purl.isEmpty()) {
      st.unusable++;
      st.diags.add(Diagnostic.warn(st.file, "component '" + label + "' has no purl; skipped"));
      return;
    }
    int line = lineOf(st, purl);
    PackageUrl p;
    try {
      p = PackageUrl.parse(purl);
    } catch (IllegalArgumentException e) {
      st.unusable++;
      st.diags.add(Diagnostic.warn(st.file, line, e.getMessage() + "; component skipped"));
      return;
    }
    if (!p.type().equals("maven")) {
      st.nonMaven++;
      st.diags.add(
          Diagnostic.info(st.file, "component " + purl + " is not a Maven package; not checked"));
      return;
    }
    String versionText = p.version().isEmpty() ? c.path("version").asText("") : p.version();
    try {
      Coordinate coord = new Coordinate(p.namespace(), p.name());
      MavenVersion v = MavenVersion.parse(versionText);
      String scope = c.path("scope").asText("required");
      boolean dev = scope.equals("excluded");
      st.out.add(
          new Dependency(
              coord, v, scope, dev, "components", SourceLocation.of(st.file, line), licenses(c)));
    } catch (IllegalArgumentException e) {
      st.unusable++;
      st.diags.add(
          Diagnostic.warn(st.file, line, purl + ": " + e.getMessage() + "; component skipped"));
    }
  }

  private static int lineOf(State st, String purl) {
    int idx = st.text.indexOf(purl, st.searchFrom);
    if (idx < 0) {
      idx = st.text.indexOf(purl);
    }
    if (idx < 0) {
      return 0;
    }
    st.searchFrom = idx + purl.length();
    int from = 0;
    int line = 1;
    if (idx >= st.countedTo) {
      from = st.countedTo;
      line = st.countedLine;
    }
    for (int i = from; i < idx; i++) {
      if (st.text.charAt(i) == '\n') {
        line++;
      }
    }
    st.countedTo = idx;
    st.countedLine = line;
    return line;
  }

  /** The component's license expression, or null when it lists none. */
  static String licenses(JsonNode component) {
    JsonNode ls = component.get("licenses");
    if (ls == null || !ls.isArray() || ls.isEmpty()) {
      return null;
    }
    List<String> parts = new ArrayList<>();
    for (JsonNode entry : ls) {
      if (entry.hasNonNull("expression")) {
        parts.add(entry.get("expression").asText());
        continue;
      }
      JsonNode lic = entry.get("license");
      if (lic == null || !lic.isObject()) {
        continue;
      }
      if (lic.hasNonNull("id")) {
        parts.add(lic.get("id").asText());
      } else if (lic.hasNonNull("name")) {
        parts.add("LicenseRef-" + lic.get("name").asText().replaceAll("[^A-Za-z0-9.-]+", "-"));
      }
    }
    if (parts.isEmpty()) {
      return null;
    }
    if (parts.size() == 1) {
      return parts.get(0);
    }
    List<String> wrapped = new ArrayList<>();
    for (String p : parts) {
      wrapped.add(p.contains(" ") ? "(" + p + ")" : p);
    }
    return String.join(" AND ", wrapped);
  }
}
