package io.github.arjunpotluri7spec.depwatch.advisory;

import static io.github.arjunpotluri7spec.depwatch.TestData.range;
import static io.github.arjunpotluri7spec.depwatch.TestData.v;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.arjunpotluri7spec.depwatch.version.MavenVersion;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/** OSV ECOSYSTEM event semantics (https://ossf.github.io/osv-schema/, "Evaluation"). */
class OsvRangeTest {

  @ParameterizedTest(name = "{0} affected={1}")
  @CsvSource({
    "2.0-beta8, false",
    "2.0-beta9, true",
    "2.0, true",
    "2.14.1, true",
    "2.15.0-rc1, true",
    "2.15.0, false",
    "2.15.0.0, false",
    "3.0, false"
  })
  void introducedFixedIsHalfOpen(String version, boolean affected) {
    OsvRange r = range("introduced:2.0-beta9", "fixed:2.15.0");
    assertThat(r.affects(v(version))).isEqualTo(affected);
  }

  @ParameterizedTest(name = "{0} affected={1}")
  @CsvSource({
    "0.1, true",
    "1.0-alpha, true",
    "1.33, true",
    "1.33.0, true",
    "1.33.1, false",
    "2, false"
  })
  void lastAffectedIsInclusiveAndIntroducedZeroMeansEverything(String version, boolean affected) {
    OsvRange r = range("introduced:0", "last_affected:1.33");
    assertThat(r.affects(v(version))).isEqualTo(affected);
  }

  @Test
  void introducedWithoutEndAffectsEverythingAfter() {
    OsvRange r = range("introduced:3.0");
    assertThat(r.affects(v("2.9"))).isFalse();
    assertThat(r.affects(v("3.0"))).isTrue();
    assertThat(r.affects(v("99"))).isTrue();
    assertThat(r.intervals())
        .singleElement()
        .satisfies(i -> assertThat(i.notation()).isEqualTo("[3.0, )"));
  }

  @Test
  void multiplePairsInOneRange() {
    OsvRange r =
        range(
            "introduced:2.9.0",
            "fixed:2.9.10.8",
            "introduced:2.10.0",
            "fixed:2.10.5.1",
            "introduced:2.11.0",
            "fixed:2.11.4");
    assertThat(r.affects(v("2.9.10.7"))).isTrue();
    assertThat(r.affects(v("2.9.10.8"))).isFalse();
    assertThat(r.affects(v("2.9.11"))).isFalse();
    assertThat(r.affects(v("2.10.1"))).isTrue();
    assertThat(r.affects(v("2.10.5.1"))).isFalse();
    assertThat(r.affects(v("2.11.3"))).isTrue();
    assertThat(r.affects(v("2.12.0"))).isFalse();
    assertThat(r.intervals()).hasSize(3);
    assertThat(r.fixVersions()).containsExactly(v("2.9.10.8"), v("2.10.5.1"), v("2.11.4"));
  }

  @Test
  void eventsAreSortedBeforeEvaluation() {
    OsvRange r = range("fixed:2.0", "introduced:1.0");
    assertThat(r.events().get(0).kind()).isEqualTo(RangeEvent.Kind.INTRODUCED);
    assertThat(r.affects(v("1.5"))).isTrue();
    assertThat(r.affects(v("2.0"))).isFalse();
  }

  @Test
  void limitCapsTheRange() {
    OsvRange r = range("introduced:1.0", "limit:1.5");
    assertThat(r.affects(v("1.4"))).isTrue();
    assertThat(r.affects(v("1.5"))).isFalse();
    assertThat(r.affects(v("2.0"))).isFalse();
    assertThat(r.intervals().get(0).notation()).isEqualTo("[1.0, 1.5)");
  }

  @Test
  void fixedBeforeAnyIntroducedHasNoEffect() {
    OsvRange r = range("fixed:0.5", "introduced:1.0", "fixed:2.0");
    assertThat(r.affects(v("0.4"))).isFalse();
    assertThat(r.affects(v("1.0"))).isTrue();
    assertThat(r.intervals()).hasSize(1);
  }

  @Test
  void intervalNotationAndEventsText() {
    OsvRange.Interval i = range("introduced:2.0-beta9", "fixed:2.15.0").intervals().get(0);
    assertThat(i.notation()).isEqualTo("[2.0-beta9, 2.15.0)");
    assertThat(i.eventsText()).isEqualTo("introduced 2.0-beta9, fixed 2.15.0");
    OsvRange.Interval z = range("introduced:0", "last_affected:1.33").intervals().get(0);
    assertThat(z.notation()).isEqualTo("(, 1.33]");
    assertThat(z.eventsText()).contains("last_affected 1.33");
  }

  /** The interval view used in explanations must agree with the OSV algorithm everywhere. */
  @Test
  void intervalsAgreeWithEvaluationAlgorithm() {
    List<OsvRange> ranges =
        List.of(
            range("introduced:0", "fixed:1.0"),
            range("introduced:1.0", "fixed:2.0", "introduced:3.0"),
            range("introduced:1.0", "last_affected:1.5", "introduced:2.0", "fixed:2.5"),
            range("introduced:1.0-alpha", "fixed:1.0", "introduced:1.0-sp", "limit:1.1"),
            range("introduced:1.0", "introduced:1.2", "fixed:1.4"));
    List<String> probes =
        List.of(
            "0",
            "0.1",
            "1.0-alpha",
            "1.0-rc1",
            "1.0",
            "1.0-sp",
            "1.0.1",
            "1.1",
            "1.2",
            "1.4",
            "1.5",
            "1.5.1",
            "2.0",
            "2.4",
            "2.5",
            "3.0",
            "3.1",
            "10");
    for (OsvRange r : ranges) {
      for (String p : probes) {
        MavenVersion pv = v(p);
        boolean inInterval = r.intervals().stream().anyMatch(i -> i.contains(pv));
        assertThat(inInterval).as("%s in %s", p, r).isEqualTo(r.affects(pv));
      }
    }
  }

  @Test
  void eventFactoryValidates() {
    assertThat(RangeEvent.of(RangeEvent.Kind.INTRODUCED, "0").isIntroducedZero()).isTrue();
    assertThat(RangeEvent.of(RangeEvent.Kind.FIXED, "0").version()).isEqualTo(v("0"));
    assertThatThrownBy(() -> RangeEvent.Kind.fromKey("patched"))
        .hasMessageContaining("unknown range event");
  }
}
