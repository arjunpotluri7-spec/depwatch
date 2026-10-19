package io.github.arjunpotluri7spec.depwatch.advisory;

import io.github.arjunpotluri7spec.depwatch.model.Coordinate;
import io.github.arjunpotluri7spec.depwatch.model.Severity;
import java.util.List;

/**
 * An OSV advisory, reduced to what Depwatch uses.
 *
 * @param severitySource how {@code severity} was obtained, for explanations
 * @param withdrawn the OSV {@code withdrawn} timestamp, or null; withdrawn advisories are never
 *     matched
 * @param sourceFile the database file the record came from
 */
public record Advisory(
    String id,
    List<String> aliases,
    String summary,
    String details,
    Severity severity,
    String severitySource,
    String published,
    String modified,
    String withdrawn,
    List<AffectedPackage> affected,
    List<Reference> references,
    String sourceFile) {

  public Advisory {
    aliases = List.copyOf(aliases);
    affected = List.copyOf(affected);
    references = List.copyOf(references);
    summary = summary == null ? "" : summary;
    details = details == null ? "" : details;
  }

  public boolean isWithdrawn() {
    return withdrawn != null;
  }

  public List<AffectedPackage> affectedFor(Coordinate c) {
    return affected.stream().filter(a -> a.coordinate().equals(c)).toList();
  }

  /** The summary, or the first line of the details when there is no summary. */
  public String title() {
    if (!summary.isBlank()) {
      return summary.strip();
    }
    String firstLine = details.strip().lines().findFirst().orElse("");
    return firstLine.length() > 200 ? firstLine.substring(0, 197) + "..." : firstLine;
  }
}
