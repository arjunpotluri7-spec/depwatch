package io.github.arjunpotluri7spec.depwatch.advisory;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.arjunpotluri7spec.depwatch.model.Severity;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

/** Base scores checked against the FIRST CVSS v3.1 calculator for well-known vectors. */
class Cvss3Test {

  @ParameterizedTest(name = "{0} = {1}")
  @CsvSource({
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H, 9.8, CRITICAL",
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H, 10.0, CRITICAL",
    "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H, 8.8, HIGH",
    "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H, 8.1, HIGH",
    "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H, 7.8, HIGH",
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H, 7.5, HIGH",
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N, 6.1, MEDIUM",
    "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N, 5.9, MEDIUM",
    "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N, 5.5, MEDIUM",
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N, 5.3, MEDIUM",
    "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H, 9.8, CRITICAL",
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, 0.0, LOW"
  })
  void knownScores(String vector, double score, Severity severity) {
    Cvss3.Score s = Cvss3.score(vector);
    assertThat(s.baseScore()).isEqualTo(score);
    assertThat(s.severity()).isEqualTo(severity);
  }

  @Test
  void temporalMetricsAreIgnored() {
    assertThat(Cvss3.score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O").baseScore())
        .isEqualTo(9.8);
  }

  @Test
  void roundUpMatchesSpecification() {
    assertThat(Cvss3.roundUp(4.02)).isEqualTo(4.1);
    assertThat(Cvss3.roundUp(4.0)).isEqualTo(4.0);
    assertThat(Cvss3.roundUp(4.000000001)).isEqualTo(4.0);
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/ZZ:1",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A"
      })
  void rejectsInvalidVectors(String vector) {
    assertThatThrownBy(() -> Cvss3.score(vector)).isInstanceOf(IllegalArgumentException.class);
  }
}
