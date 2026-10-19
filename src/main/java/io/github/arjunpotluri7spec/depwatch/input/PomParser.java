package io.github.arjunpotluri7spec.depwatch.input;

import io.github.arjunpotluri7spec.depwatch.model.Coordinate;
import io.github.arjunpotluri7spec.depwatch.model.Dependency;
import io.github.arjunpotluri7spec.depwatch.model.Diagnostic;
import io.github.arjunpotluri7spec.depwatch.model.SourceLocation;
import io.github.arjunpotluri7spec.depwatch.version.InvalidVersionException;
import io.github.arjunpotluri7spec.depwatch.version.MavenVersion;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Reads declared dependencies from a single {@code pom.xml}.
 *
 * <p>Handles {@code <properties>} with {@code ${...}} interpolation, the {@code project.*} and
 * {@code project.parent.*} built-ins, and versions taken from this POM's {@code
 * <dependencyManagement>}. The {@code <parent>} coordinates are recorded, but the parent POM, and
 * any BOM imported with {@code <scope>import</scope>}, is never fetched: there is no network access
 * and no local repository lookup. Dependencies whose version would come from those places are
 * reported as unresolved rather than guessed.
 *
 * <p>Managed dependencies are audited too (they pin versions that transitive dependencies resolve
 * to), unless the same coordinate is also declared in {@code <dependencies>}.
 */
public final class PomParser {

  private PomParser() {}

  /** Coordinates from {@code <parent>}, kept for the report. */
  public record Parent(String groupId, String artifactId, String version) {}

  private record RawDep(
      SecureXml.Element element,
      String groupId,
      String artifactId,
      String version,
      String scope,
      String origin) {}

  public static ParsedInput parse(byte[] data, String file) {
    SecureXml.Element root = SecureXml.parse(data, file);
    if (!root.name().equals("project")) {
      throw new io.github.arjunpotluri7spec.depwatch.util.DepwatchException(
          file + ": root element is <" + root.name() + ">, expected <project>");
    }
    List<Diagnostic> diags = new ArrayList<>();

    Optional<SecureXml.Element> parentEl = root.child("parent");
    Parent parent =
        parentEl
            .map(
                p ->
                    new Parent(
                        p.childText("groupId").orElse(""),
                        p.childText("artifactId").orElse(""),
                        p.childText("version").orElse("")))
            .orElse(null);
    if (parent != null) {
      diags.add(
          Diagnostic.info(
              file,
              "parent POM "
                  + parent.groupId()
                  + ":"
                  + parent.artifactId()
                  + ":"
                  + parent.version()
                  + " is not resolved (offline); versions and properties it defines are"
                  + " unknown"));
    }

    Map<String, String> props = new LinkedHashMap<>();
    root.child("properties")
        .ifPresent(
            p -> {
              for (SecureXml.Element e : p.children()) {
                props.put(e.name(), e.text());
              }
            });
    String groupId = root.childText("groupId").orElse(parent == null ? "" : parent.groupId());
    String artifactId = root.childText("artifactId").orElse("");
    String version = root.childText("version").orElse(parent == null ? "" : parent.version());
    Map<String, String> builtIns = new HashMap<>();
    builtIns.put("project.groupId", groupId);
    builtIns.put("project.artifactId", artifactId);
    builtIns.put("project.version", version);
    builtIns.put("pom.groupId", groupId);
    builtIns.put("pom.artifactId", artifactId);
    builtIns.put("pom.version", version);
    builtIns.put("groupId", groupId);
    builtIns.put("artifactId", artifactId);
    builtIns.put("version", version);
    if (parent != null) {
      builtIns.put("project.parent.groupId", parent.groupId());
      builtIns.put("project.parent.artifactId", parent.artifactId());
      builtIns.put("project.parent.version", parent.version());
      builtIns.put("parent.version", parent.version());
    }
    Map<String, String> all = new HashMap<>(props);
    all.putAll(builtIns);
    PropertyResolver resolver = new PropertyResolver(all);

    List<RawDep> managed = new ArrayList<>();
    root.child("dependencyManagement")
        .flatMap(dm -> dm.child("dependencies"))
        .ifPresent(
            ds ->
                ds.children("dependency")
                    .forEach(d -> managed.add(raw(d, "dependencyManagement"))));
    List<RawDep> declared = new ArrayList<>();
    root.child("dependencies")
        .ifPresent(
            ds -> ds.children("dependency").forEach(d -> declared.add(raw(d, "dependencies"))));

    int[] unusable = {0};
    Map<String, String> managedVersions = new HashMap<>();
    List<Resolved> managedResolved = new ArrayList<>();
    for (RawDep m : managed) {
      Optional<Resolved> r = resolve(m, resolver, Map.of(), file, diags, unusable);
      if (r.isEmpty()) {
        continue;
      }
      if (r.get().scope.equals("import")) {
        diags.add(
            Diagnostic.warn(
                file,
                m.element().line(),
                "BOM "
                    + r.get().coordinate
                    + " is imported; its managed versions are not resolved (offline)"));
        continue;
      }
      managedVersions.put(r.get().coordinate.toString(), r.get().versionText);
      managedResolved.add(r.get());
    }

    List<Dependency> out = new ArrayList<>();
    Set<String> declaredKeys = new HashSet<>();
    for (RawDep d : declared) {
      Optional<Resolved> r = resolve(d, resolver, managedVersions, file, diags, unusable);
      if (r.isEmpty()) {
        continue;
      }
      declaredKeys.add(r.get().coordinate.toString());
      toDependency(r.get(), file, diags, unusable).ifPresent(out::add);
    }
    for (Resolved m : managedResolved) {
      if (!declaredKeys.contains(m.coordinate.toString())) {
        toDependency(m, file, diags, unusable).ifPresent(out::add);
      }
    }
    return new ParsedInput(file, InputFormat.MAVEN_POM, out, diags, unusable[0], false);
  }

  private static RawDep raw(SecureXml.Element d, String origin) {
    return new RawDep(
        d,
        d.childText("groupId").orElse(""),
        d.childText("artifactId").orElse(""),
        d.childText("version").orElse(""),
        d.childText("scope").orElse(""),
        origin);
  }

  private static final class Resolved {
    Coordinate coordinate;
    String versionText;
    String scope;
    String origin;
    int line;
  }

  private static Optional<Resolved> resolve(
      RawDep d,
      PropertyResolver resolver,
      Map<String, String> managedVersions,
      String file,
      List<Diagnostic> diags,
      int[] unusable) {
    int line =
        d.element().child("artifactId").map(SecureXml.Element::line).orElse(d.element().line());
    PropertyResolver.Result g = resolver.resolve(d.groupId());
    PropertyResolver.Result a = resolver.resolve(d.artifactId());
    if (!g.complete() || !a.complete() || g.value().isEmpty() || a.value().isEmpty()) {
      unusable[0]++;
      List<String> why = new ArrayList<>(g.problems());
      why.addAll(a.problems());
      diags.add(
          Diagnostic.warn(
              file,
              line,
              "dependency in <"
                  + d.origin()
                  + "> has no usable groupId/artifactId"
                  + (why.isEmpty() ? "" : " (" + String.join("; ", why) + ")")
                  + "; skipped"));
      return Optional.empty();
    }
    Coordinate coordinate;
    try {
      coordinate = new Coordinate(g.value(), a.value());
    } catch (IllegalArgumentException e) {
      unusable[0]++;
      diags.add(Diagnostic.warn(file, line, "invalid dependency coordinate: " + e.getMessage()));
      return Optional.empty();
    }
    String versionText = d.version();
    String origin = d.origin();
    if (versionText.isEmpty()) {
      String managedVersion = managedVersions.get(coordinate.toString());
      if (managedVersion == null) {
        unusable[0]++;
        diags.add(
            Diagnostic.warn(
                file,
                line,
                coordinate
                    + " has no version here and is not in this POM's <dependencyManagement>; it"
                    + " probably comes from the parent POM or an imported BOM, which are not"
                    + " resolved offline; skipped"));
        return Optional.empty();
      }
      versionText = managedVersion;
      origin = "dependencies (version from dependencyManagement)";
    } else {
      PropertyResolver.Result v = resolver.resolve(versionText);
      if (!v.complete()) {
        unusable[0]++;
        diags.add(
            Diagnostic.warn(
                file,
                line,
                coordinate
                    + " version '"
                    + versionText
                    + "' cannot be resolved: "
                    + String.join("; ", v.problems())
                    + "; skipped"));
        return Optional.empty();
      }
      versionText = v.value();
    }
    PropertyResolver.Result scope = resolver.resolve(d.scope());
    Resolved r = new Resolved();
    r.coordinate = coordinate;
    r.versionText = versionText;
    r.scope = scope.value().isEmpty() ? "compile" : scope.value().toLowerCase(Locale.ROOT);
    r.origin = origin;
    r.line = line;
    return Optional.of(r);
  }

  private static Optional<Dependency> toDependency(
      Resolved r, String file, List<Diagnostic> diags, int[] unusable) {
    String v = r.versionText;
    if (v.startsWith("[") || v.startsWith("(")) {
      unusable[0]++;
      diags.add(
          Diagnostic.warn(
              file,
              r.line,
              r.coordinate
                  + " uses the version range "
                  + v
                  + "; the version Maven would pick is unknown offline (scan a lockfile or SBOM"
                  + " instead); skipped"));
      return Optional.empty();
    }
    MavenVersion version;
    try {
      version = MavenVersion.parse(v);
    } catch (InvalidVersionException e) {
      unusable[0]++;
      diags.add(Diagnostic.warn(file, r.line, r.coordinate + ": " + e.getMessage() + "; skipped"));
      return Optional.empty();
    }
    boolean dev = r.scope.equals("test");
    return Optional.of(
        new Dependency(
            r.coordinate, version, r.scope, dev, r.origin, SourceLocation.of(file, r.line), null));
  }
}
