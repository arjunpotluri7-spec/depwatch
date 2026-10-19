package io.github.arjunpotluri7spec.depwatch.advisory;

import io.github.arjunpotluri7spec.depwatch.version.MavenVersion;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

/**
 * An OSV {@code ECOSYSTEM} range: a list of events evaluated with Maven version ordering.
 *
 * <p>Semantics follow the OSV schema's evaluation algorithm (https://ossf.github.io/osv-schema/
 * section "Evaluation"): sort the events by version ({@code introduced: "0"} first), start
 * unaffected, and walk the events up to the version being checked. {@code introduced} at or below
 * the version turns "affected" on; {@code fixed} at or below it turns it off; {@code last_affected}
 * strictly below it turns it off. A version at or above any {@code limit} is never affected.
 */
public final class OsvRange {

  /** A contiguous affected interval derived from the events, used to explain matches. */
  public record Interval(
      RangeEvent start, MavenVersion upper, boolean upperInclusive, RangeEvent end) {

    public boolean contains(MavenVersion v) {
      if (start.version() != null && v.compareTo(start.version()) < 0) {
        return false;
      }
      if (upper == null) {
        return true;
      }
      int c = v.compareTo(upper);
      return c < 0 || (c == 0 && upperInclusive);
    }

    /** Interval notation, e.g. {@code [2.0-beta9, 2.15.0)} or {@code (, 1.33]}. */
    public String notation() {
      String lower = start.version() == null ? "(" : "[" + start.raw();
      String up = upper == null ? ")" : upper + (upperInclusive ? "]" : ")");
      return lower + ", " + up;
    }

    /** The events that bound this interval, e.g. {@code introduced 2.0-beta9, fixed 2.15.0}. */
    public String eventsText() {
      String first =
          start.version() == null ? "introduced 0 (from the first version)" : start.toString();
      return end == null ? first + ", no fix recorded" : first + ", " + end;
    }
  }

  private static final Comparator<RangeEvent> EVENT_ORDER =
      (a, b) -> {
        if (a.version() == null || b.version() == null) {
          if (a.version() == null && b.version() == null) {
            return 0;
          }
          return a.version() == null ? -1 : 1;
        }
        int c = a.version().compareTo(b.version());
        return c != 0 ? c : a.kind().compareTo(b.kind());
      };

  private final String type;
  private final List<RangeEvent> events;
  private final List<Interval> intervals;

  public OsvRange(String type, List<RangeEvent> events) {
    this.type = type;
    List<RangeEvent> sorted = new ArrayList<>(events);
    sorted.sort(EVENT_ORDER);
    this.events = List.copyOf(sorted);
    this.intervals = List.copyOf(buildIntervals(this.events));
  }

  public String type() {
    return type;
  }

  /** Events sorted in evaluation order. */
  public List<RangeEvent> events() {
    return events;
  }

  public List<Interval> intervals() {
    return intervals;
  }

  /** The OSV evaluation algorithm. This is the authority; {@link #intervals()} only explains. */
  public boolean affects(MavenVersion v) {
    for (RangeEvent e : events) {
      if (e.kind() == RangeEvent.Kind.LIMIT && v.compareTo(e.version()) >= 0) {
        return false;
      }
    }
    boolean affected = false;
    for (RangeEvent e : events) {
      switch (e.kind()) {
        case INTRODUCED -> {
          if (e.version() == null || v.compareTo(e.version()) >= 0) {
            affected = true;
          }
        }
        case FIXED -> {
          if (v.compareTo(e.version()) >= 0) {
            affected = false;
          }
        }
        case LAST_AFFECTED -> {
          if (v.compareTo(e.version()) > 0) {
            affected = false;
          }
        }
        case LIMIT -> {
          // handled above
        }
      }
    }
    return affected;
  }

  /** The interval containing the version, if it is affected. */
  public Optional<Interval> intervalContaining(MavenVersion v) {
    if (!affects(v)) {
      return Optional.empty();
    }
    return intervals.stream().filter(i -> i.contains(v)).findFirst();
  }

  /** Versions recorded as the first unaffected version after an affected interval. */
  public List<MavenVersion> fixVersions() {
    List<MavenVersion> out = new ArrayList<>();
    for (RangeEvent e : events) {
      if (e.kind() == RangeEvent.Kind.FIXED || e.kind() == RangeEvent.Kind.LIMIT) {
        out.add(e.version());
      }
    }
    return out;
  }

  private static List<Interval> buildIntervals(List<RangeEvent> sorted) {
    List<Interval> out = new ArrayList<>();
    RangeEvent open = null;
    MavenVersion limit = null;
    for (RangeEvent e : sorted) {
      if (e.kind() == RangeEvent.Kind.LIMIT && (limit == null || e.version().isBefore(limit))) {
        limit = e.version();
      }
    }
    for (RangeEvent e : sorted) {
      if (limit != null && e.version() != null && e.version().compareTo(limit) >= 0) {
        break;
      }
      switch (e.kind()) {
        case INTRODUCED -> {
          if (open == null) {
            open = e;
          }
        }
        case FIXED -> {
          if (open != null) {
            out.add(new Interval(open, e.version(), false, e));
            open = null;
          }
        }
        case LAST_AFFECTED -> {
          if (open != null) {
            out.add(new Interval(open, e.version(), true, e));
            open = null;
          }
        }
        case LIMIT -> {
          // limits only cut intervals; handled below
        }
      }
    }
    if (open != null) {
      RangeEvent limitEvent = null;
      for (RangeEvent e : sorted) {
        if (e.kind() == RangeEvent.Kind.LIMIT && e.version().equals(limit)) {
          limitEvent = e;
          break;
        }
      }
      out.add(new Interval(open, limit, false, limitEvent));
    }
    return out;
  }

  @Override
  public String toString() {
    StringBuilder b = new StringBuilder();
    for (Interval i : intervals) {
      if (b.length() > 0) {
        b.append(" and ");
      }
      b.append(i.notation());
    }
    return b.length() == 0 ? "(no affected interval)" : b.toString();
  }
}
