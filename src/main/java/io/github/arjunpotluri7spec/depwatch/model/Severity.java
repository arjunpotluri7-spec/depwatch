package io.github.arjunpotluri7spec.depwatch.model;

import java.util.Locale;
import java.util.Optional;

/**
 * Qualitative severity. {@link #UNKNOWN} is used when an advisory carries no usable severity; for
 * {@code --fail-on} gating it counts as {@link #HIGH} so that missing data never hides a finding.
 */
public enum Severity {
  UNKNOWN(3, 35),
  LOW(1, 10),
  MEDIUM(2, 20),
  HIGH(3, 40),
  CRITICAL(4, 50);

  private final int gateRank;
  private final int sortRank;

  Severity(int gateRank, int sortRank) {
    this.gateRank = gateRank;
    this.sortRank = sortRank;
  }

  /** Rank used for {@code --fail-on} comparisons. */
  public int gateRank() {
    return gateRank;
  }

  /** Rank used for sorting reports (higher first): unknown sorts between high and medium. */
  public int sortRank() {
    return sortRank;
  }

  public boolean atLeast(Severity threshold) {
    return gateRank >= threshold.gateRank;
  }

  public String label() {
    return name().toLowerCase(Locale.ROOT);
  }

  /**
   * Parses a qualitative label. Accepts the OSV / GitHub {@code MODERATE} as {@link #MEDIUM}.
   * Returns empty for anything else.
   */
  public static Optional<Severity> fromLabel(String text) {
    if (text == null) {
      return Optional.empty();
    }
    String t = text.trim().toUpperCase(Locale.ROOT);
    return switch (t) {
      case "LOW" -> Optional.of(LOW);
      case "MEDIUM", "MODERATE" -> Optional.of(MEDIUM);
      case "HIGH" -> Optional.of(HIGH);
      case "CRITICAL" -> Optional.of(CRITICAL);
      case "UNKNOWN" -> Optional.of(UNKNOWN);
      default -> Optional.empty();
    };
  }
}
