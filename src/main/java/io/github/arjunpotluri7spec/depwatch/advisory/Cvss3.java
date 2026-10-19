package io.github.arjunpotluri7spec.depwatch.advisory;

import io.github.arjunpotluri7spec.depwatch.model.Severity;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * CVSS v3.0 / v3.1 base score calculator.
 *
 * <p>Formulas and the qualitative rating scale are from the FIRST "CVSS v3.1 Specification
 * Document", sections 7.1 (base metric equations), 7.4 (metric values), Appendix A (Roundup) and
 * section 5 (qualitative severity rating scale). Only the base score is computed; temporal and
 * environmental metrics in a vector are validated and ignored.
 */
public final class Cvss3 {

  private static final Set<String> BASE = Set.of("AV", "AC", "PR", "UI", "S", "C", "I", "A");
  private static final Set<String> OPTIONAL =
      Set.of("E", "RL", "RC", "CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA");

  private Cvss3() {}

  /** A parsed base score. */
  public record Score(String vector, double baseScore) {

    /**
     * Qualitative rating from section 5 of the specification: 0.1-3.9 low, 4.0-6.9 medium, 7.0-8.9
     * high, 9.0-10.0 critical. A score of 0.0 ("none") is reported as low.
     */
    public Severity severity() {
      if (baseScore >= 9.0) {
        return Severity.CRITICAL;
      }
      if (baseScore >= 7.0) {
        return Severity.HIGH;
      }
      if (baseScore >= 4.0) {
        return Severity.MEDIUM;
      }
      return Severity.LOW;
    }
  }

  /**
   * Computes the base score of a CVSS v3.x vector such as {@code
   * CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H}.
   *
   * @throws IllegalArgumentException naming the problem if the vector is invalid
   */
  public static Score score(String vector) {
    if (vector == null || vector.length() > 256) {
      throw new IllegalArgumentException("CVSS vector is missing or too long");
    }
    String[] parts = vector.trim().split("/");
    if (parts.length == 0 || !(parts[0].equals("CVSS:3.0") || parts[0].equals("CVSS:3.1"))) {
      throw new IllegalArgumentException(
          "CVSS vector '" + vector + "' does not start with CVSS:3.0/ or CVSS:3.1/");
    }
    Map<String, String> m = new HashMap<>();
    for (int i = 1; i < parts.length; i++) {
      String[] kv = parts[i].split(":", -1);
      if (kv.length != 2 || kv[1].isEmpty()) {
        throw new IllegalArgumentException("CVSS vector has a malformed metric '" + parts[i] + "'");
      }
      if (!BASE.contains(kv[0]) && !OPTIONAL.contains(kv[0])) {
        throw new IllegalArgumentException("CVSS vector has an unknown metric '" + kv[0] + "'");
      }
      if (m.put(kv[0], kv[1]) != null) {
        throw new IllegalArgumentException("CVSS vector repeats metric '" + kv[0] + "'");
      }
    }
    for (String k : BASE) {
      if (!m.containsKey(k)) {
        throw new IllegalArgumentException("CVSS vector is missing base metric '" + k + "'");
      }
    }
    boolean changed =
        switch (m.get("S")) {
          case "U" -> false;
          case "C" -> true;
          default -> throw bad("S", m.get("S"));
        };
    double av =
        switch (m.get("AV")) {
          case "N" -> 0.85;
          case "A" -> 0.62;
          case "L" -> 0.55;
          case "P" -> 0.2;
          default -> throw bad("AV", m.get("AV"));
        };
    double ac =
        switch (m.get("AC")) {
          case "L" -> 0.77;
          case "H" -> 0.44;
          default -> throw bad("AC", m.get("AC"));
        };
    double pr =
        switch (m.get("PR")) {
          case "N" -> 0.85;
          case "L" -> changed ? 0.68 : 0.62;
          case "H" -> changed ? 0.5 : 0.27;
          default -> throw bad("PR", m.get("PR"));
        };
    double ui =
        switch (m.get("UI")) {
          case "N" -> 0.85;
          case "R" -> 0.62;
          default -> throw bad("UI", m.get("UI"));
        };
    double c = cia("C", m.get("C"));
    double in = cia("I", m.get("I"));
    double a = cia("A", m.get("A"));

    double iss = 1 - ((1 - c) * (1 - in) * (1 - a));
    double impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
    double exploitability = 8.22 * av * ac * pr * ui;
    double base;
    if (impact <= 0) {
      base = 0.0;
    } else if (changed) {
      base = roundUp(Math.min(1.08 * (impact + exploitability), 10));
    } else {
      base = roundUp(Math.min(impact + exploitability, 10));
    }
    return new Score(vector.trim(), base);
  }

  private static double cia(String key, String value) {
    return switch (value) {
      case "H" -> 0.56;
      case "L" -> 0.22;
      case "N" -> 0.0;
      default -> throw bad(key, value);
    };
  }

  private static IllegalArgumentException bad(String key, String value) {
    return new IllegalArgumentException(
        "CVSS vector has an invalid value '" + value + "' for metric " + key);
  }

  /** Roundup as defined in Appendix A of the v3.1 specification (avoids floating point drift). */
  static double roundUp(double value) {
    long intInput = Math.round(value * 100000);
    if (intInput % 10000 == 0) {
      return intInput / 100000.0;
    }
    return (Math.floor(intInput / 10000.0) + 1) / 10.0;
  }
}
