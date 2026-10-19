package io.github.arjunpotluri7spec.depwatch.advisory;

import io.github.arjunpotluri7spec.depwatch.model.Coordinate;
import io.github.arjunpotluri7spec.depwatch.model.Diagnostic;
import io.github.arjunpotluri7spec.depwatch.model.Severity;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/** The loaded advisory snapshot, indexed by package. Immutable once built. */
public final class AdvisoryDatabase {

  /** Counts describing a load, for {@code db stats} and report headers. */
  public record Stats(
      String location,
      int filesRead,
      int recordsLoaded,
      int recordsSkipped,
      int withdrawn,
      int nonMavenRecords,
      int packages,
      Map<Severity, Integer> bySeverity,
      int withFix,
      int withoutFix) {}

  private final String location;
  private final List<Advisory> advisories;
  private final Map<Coordinate, List<Advisory>> byPackage;
  private final List<Diagnostic> diagnostics;
  private final int filesRead;
  private final int recordsSkipped;
  private final int nonMavenRecords;

  AdvisoryDatabase(
      String location,
      List<Advisory> advisories,
      List<Diagnostic> diagnostics,
      int filesRead,
      int recordsSkipped,
      int nonMavenRecords) {
    this.location = location;
    this.advisories = List.copyOf(advisories);
    this.diagnostics = List.copyOf(diagnostics);
    this.filesRead = filesRead;
    this.recordsSkipped = recordsSkipped;
    this.nonMavenRecords = nonMavenRecords;
    Map<Coordinate, List<Advisory>> index = new TreeMap<>();
    for (Advisory a : this.advisories) {
      for (AffectedPackage p : a.affected()) {
        List<Advisory> list = index.computeIfAbsent(p.coordinate(), k -> new ArrayList<>());
        if (!list.contains(a)) {
          list.add(a);
        }
      }
    }
    Map<Coordinate, List<Advisory>> frozen = new LinkedHashMap<>();
    index.forEach((k, v) -> frozen.put(k, List.copyOf(v)));
    this.byPackage = frozen;
  }

  /** Builds a database from records already in memory (used by tests and embedders). */
  public static AdvisoryDatabase of(String location, List<Advisory> advisories) {
    return new AdvisoryDatabase(location, advisories, List.of(), 0, 0, 0);
  }

  public String location() {
    return location;
  }

  /** All Maven advisories, including withdrawn ones. */
  public List<Advisory> advisories() {
    return advisories;
  }

  /** Every advisory naming the package, including withdrawn ones, in id order. */
  public List<Advisory> forPackage(Coordinate c) {
    return byPackage.getOrDefault(c, List.of());
  }

  /** Warnings produced while loading, such as skipped malformed records. */
  public List<Diagnostic> diagnostics() {
    return diagnostics;
  }

  public Stats stats() {
    Map<Severity, Integer> bySeverity = new EnumMap<>(Severity.class);
    for (Severity s : Severity.values()) {
      bySeverity.put(s, 0);
    }
    int withdrawn = 0;
    int withFix = 0;
    int withoutFix = 0;
    for (Advisory a : advisories) {
      if (a.isWithdrawn()) {
        withdrawn++;
        continue;
      }
      bySeverity.merge(a.severity(), 1, Integer::sum);
      boolean fix =
          a.affected().stream()
              .flatMap(p -> p.ranges().stream())
              .anyMatch(r -> !r.fixVersions().isEmpty());
      if (fix) {
        withFix++;
      } else {
        withoutFix++;
      }
    }
    return new Stats(
        location,
        filesRead,
        advisories.size(),
        recordsSkipped,
        withdrawn,
        nonMavenRecords,
        byPackage.size(),
        bySeverity,
        withFix,
        withoutFix);
  }
}
