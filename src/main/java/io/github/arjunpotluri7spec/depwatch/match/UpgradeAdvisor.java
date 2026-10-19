package io.github.arjunpotluri7spec.depwatch.match;

import io.github.arjunpotluri7spec.depwatch.advisory.Advisory;
import io.github.arjunpotluri7spec.depwatch.advisory.AffectedPackage;
import io.github.arjunpotluri7spec.depwatch.advisory.OsvRange;
import io.github.arjunpotluri7spec.depwatch.advisory.RangeEvent;
import io.github.arjunpotluri7spec.depwatch.model.Coordinate;
import io.github.arjunpotluri7spec.depwatch.version.MavenVersion;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.TreeSet;

/**
 * Computes the smallest safe upgrade.
 *
 * <p>Offline there is no list of published versions, so the candidates are the versions the
 * advisories themselves name as fixes ({@code fixed} and {@code limit} events). A candidate is safe
 * when no active advisory for the package affects it. The suggestion is the lowest safe candidate
 * that is at or above the current version, preferring the current major version and otherwise
 * taking the lowest safe version in a later major (and saying so).
 */
public final class UpgradeAdvisor {

  private UpgradeAdvisor() {}

  /**
   * @param advisories every advisory for the package; withdrawn ones are ignored
   */
  public static UpgradeSuggestion suggest(
      List<Advisory> advisories, Coordinate pkg, MavenVersion current) {
    List<Advisory> active = advisories.stream().filter(a -> !a.isWithdrawn()).toList();
    List<String> affectingIds = idsAffecting(active, pkg, current);
    if (affectingIds.isEmpty()) {
      return new UpgradeSuggestion(
          UpgradeSuggestion.Kind.NOT_NEEDED,
          null,
          current + " is not affected by any known advisory; no upgrade needed.");
    }

    TreeSet<MavenVersion> candidates = new TreeSet<>();
    for (Advisory a : active) {
      for (AffectedPackage p : a.affectedFor(pkg)) {
        for (OsvRange r : p.ranges()) {
          for (MavenVersion fix : r.fixVersions()) {
            if (fix.isAfter(current)) {
              candidates.add(fix);
            }
          }
        }
      }
    }

    List<String> rejected = new ArrayList<>();
    List<MavenVersion> safe = new ArrayList<>();
    for (MavenVersion c : candidates) {
      List<String> ids = idsAffecting(active, pkg, c);
      if (ids.isEmpty()) {
        safe.add(c);
      } else {
        rejected.add(c + " (still affected by " + String.join(", ", ids) + ")");
      }
    }

    String skippedText =
        rejected.isEmpty() ? "" : " Skipped fix versions: " + String.join("; ", rejected) + ".";
    Optional<BigInteger> major = current.major();
    for (MavenVersion s : safe) {
      if (major.isPresent() && major.equals(s.major())) {
        return new UpgradeSuggestion(
            UpgradeSuggestion.Kind.SAME_MAJOR,
            s,
            "Upgrade to "
                + s
                + preRelease(s)
                + ": the lowest recorded fix version above "
                + current
                + " that no known advisory affects, within the same major version ("
                + major.get()
                + ".x)."
                + skippedText);
      }
    }
    if (!safe.isEmpty()) {
      MavenVersion s = safe.get(0);
      String line = major.map(m -> m + ".x").orElse("the current version line");
      String to = s.major().map(m -> m + ".x").orElse(s.toString());
      return new UpgradeSuggestion(
          UpgradeSuggestion.Kind.NEXT_MAJOR,
          s,
          "No safe version is recorded in "
              + line
              + ". The lowest safe version is "
              + s
              + preRelease(s)
              + ", a major upgrade to "
              + to
              + "."
              + skippedText);
    }
    StringBuilder why =
        new StringBuilder("No version known to be safe is recorded in the advisory database.");
    why.append(skippedText);
    for (Advisory a : active) {
      for (AffectedPackage p : a.affectedFor(pkg)) {
        boolean anyFix = p.ranges().stream().anyMatch(r -> !r.fixVersions().isEmpty());
        for (OsvRange r : p.ranges()) {
          for (OsvRange.Interval i : r.intervals()) {
            if (i.end() != null
                && i.end().kind() == RangeEvent.Kind.LAST_AFFECTED
                && !anyFix
                && i.contains(current)) {
              why.append(' ')
                  .append(a.id())
                  .append(" affects versions up to and including ")
                  .append(i.upper())
                  .append(
                      " and names no fix; a later release may be safe, but none is named"
                          + " offline.");
            } else if (i.end() == null && i.contains(current)) {
              why.append(' ')
                  .append(a.id())
                  .append(" has no upper bound: every version from ")
                  .append(i.start().version() == null ? "the first" : i.start().raw())
                  .append(" on is affected.");
            }
          }
        }
        if (p.ranges().isEmpty() && !p.versions().isEmpty()) {
          why.append(' ')
              .append(a.id())
              .append(" lists affected versions only and records no fix version.");
        }
      }
    }
    return new UpgradeSuggestion(UpgradeSuggestion.Kind.NONE_KNOWN, null, why.toString());
  }

  private static String preRelease(MavenVersion v) {
    return v.isPreRelease() ? " (a pre-release)" : "";
  }

  private static List<String> idsAffecting(List<Advisory> active, Coordinate pkg, MavenVersion v) {
    List<String> ids = new ArrayList<>();
    for (Advisory a : active) {
      for (AffectedPackage p : a.affectedFor(pkg)) {
        if (p.affects(v)) {
          ids.add(a.id());
          break;
        }
      }
    }
    return ids;
  }
}
