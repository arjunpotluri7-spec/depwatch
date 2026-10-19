package io.github.arjunpotluri7spec.depwatch.match;

import io.github.arjunpotluri7spec.depwatch.advisory.Advisory;
import io.github.arjunpotluri7spec.depwatch.advisory.AdvisoryDatabase;
import io.github.arjunpotluri7spec.depwatch.advisory.AffectedPackage;
import io.github.arjunpotluri7spec.depwatch.advisory.OsvRange;
import io.github.arjunpotluri7spec.depwatch.model.Coordinate;
import io.github.arjunpotluri7spec.depwatch.version.MavenVersion;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/** Checks a package version against advisories and explains each result. */
public final class AdvisoryMatcher {

  private AdvisoryMatcher() {}

  /** Checks every advisory in the database that names the package, withdrawn ones included. */
  public static List<Check> checkAll(AdvisoryDatabase db, Coordinate c, MavenVersion v) {
    List<Check> out = new ArrayList<>();
    for (Advisory a : db.forPackage(c)) {
      out.add(check(a, c, v));
    }
    return out;
  }

  /** Only the advisories that affect the version. */
  public static List<Check> affecting(AdvisoryDatabase db, Coordinate c, MavenVersion v) {
    return checkAll(db, c, v).stream().filter(Check::affected).toList();
  }

  public static Check check(Advisory a, Coordinate c, MavenVersion v) {
    Optional<String[]> hit = findHit(a, c, v);
    if (a.isWithdrawn()) {
      String would =
          hit.map(h -> " (it would otherwise match: " + h[1] + ")").orElse(" (it would not match)");
      return new Check(
          a,
          Check.Status.WITHDRAWN,
          a.id() + " was withdrawn on " + a.withdrawn() + " and is ignored" + would,
          "");
    }
    if (hit.isPresent()) {
      return new Check(a, Check.Status.AFFECTED, hit.get()[1], hit.get()[0]);
    }
    return new Check(a, Check.Status.NOT_AFFECTED, notAffectedReason(a, c, v), "");
  }

  /** Returns {matchedRange, reason} for the first part of the advisory that matches. */
  private static Optional<String[]> findHit(Advisory a, Coordinate c, MavenVersion v) {
    for (AffectedPackage p : a.affectedFor(c)) {
      for (OsvRange r : p.ranges()) {
        Optional<OsvRange.Interval> i = r.intervalContaining(v);
        if (i.isPresent()) {
          String notation = i.get().notation();
          return Optional.of(
              new String[] {
                notation,
                v + " is in " + notation + " from " + a.id() + " (" + i.get().eventsText() + ")"
              });
        }
      }
      Optional<MavenVersion> listed = p.listedVersion(v);
      if (listed.isPresent()) {
        String as =
            listed.get().original().equals(v.original())
                ? ""
                : " as " + listed.get() + ", equal under Maven ordering";
        return Optional.of(
            new String[] {
              "versions list", v + " is listed as an affected version in " + a.id() + as
            });
      }
    }
    return Optional.empty();
  }

  private static String notAffectedReason(Advisory a, Coordinate c, MavenVersion v) {
    List<String> intervals = new ArrayList<>();
    int listed = 0;
    for (AffectedPackage p : a.affectedFor(c)) {
      for (OsvRange r : p.ranges()) {
        for (OsvRange.Interval i : r.intervals()) {
          intervals.add(i.notation());
        }
      }
      listed += p.versions().size();
    }
    StringBuilder b = new StringBuilder(v.toString()).append(" is not affected by ").append(a.id());
    if (!intervals.isEmpty()) {
      b.append(": outside ").append(String.join(" and ", intervals));
    }
    if (listed > 0) {
      b.append(intervals.isEmpty() ? ": " : ", ")
          .append("not among its ")
          .append(listed)
          .append(listed == 1 ? " listed version" : " listed versions");
    }
    return b.toString();
  }
}
