package io.github.arjunpotluri7spec.depwatch.match;

import static io.github.arjunpotluri7spec.depwatch.TestData.PKG;
import static io.github.arjunpotluri7spec.depwatch.TestData.advisory;
import static io.github.arjunpotluri7spec.depwatch.TestData.range;
import static io.github.arjunpotluri7spec.depwatch.TestData.v;
import static org.assertj.core.api.Assertions.assertThat;

import io.github.arjunpotluri7spec.depwatch.advisory.Advisory;
import java.util.List;
import org.junit.jupiter.api.Test;

class UpgradeAdvisorTest {

  private static UpgradeSuggestion suggest(String current, Advisory... advisories) {
    return UpgradeAdvisor.suggest(List.of(advisories), PKG, v(current));
  }

  @Test
  void notNeededWhenNotAffected() {
    UpgradeSuggestion s = suggest("2.16.0", advisory("A", range("introduced:2.0", "fixed:2.15.0")));
    assertThat(s.kind()).isEqualTo(UpgradeSuggestion.Kind.NOT_NEEDED);
    assertThat(s.target()).isEmpty();
  }

  @Test
  void picksTheFixInTheSameMajor() {
    UpgradeSuggestion s =
        suggest("2.14.1", advisory("A", range("introduced:2.0-beta9", "fixed:2.15.0")));
    assertThat(s.kind()).isEqualTo(UpgradeSuggestion.Kind.SAME_MAJOR);
    assertThat(s.target()).contains(v("2.15.0"));
    assertThat(s.explanation()).contains("same major version (2.x)");
  }

  @Test
  void skipsAFixThatAnotherAdvisoryStillAffects() {
    UpgradeSuggestion s =
        suggest(
            "2.14.1",
            advisory("A", range("introduced:2.0-beta9", "fixed:2.15.0")),
            advisory("B", range("introduced:2.15.0", "fixed:2.16.0")));
    assertThat(s.target()).contains(v("2.16.0"));
    assertThat(s.explanation()).contains("Skipped fix versions: 2.15.0 (still affected by B)");
  }

  @Test
  void picksTheLowestFixOnTheCurrentReleaseLine() {
    Advisory a =
        advisory(
            "A",
            range(
                "introduced:2.9.0",
                "fixed:2.9.10.8",
                "introduced:2.10.0",
                "fixed:2.10.5.1",
                "introduced:2.11.0",
                "fixed:2.11.4"));
    assertThat(suggest("2.10.1", a).target()).contains(v("2.10.5.1"));
    assertThat(suggest("2.9.3", a).target()).contains(v("2.9.10.8"));
  }

  @Test
  void prefersTheSameMajorOverALowerOrEqualNextMajor() {
    Advisory a = advisory("A", range("introduced:1.0", "fixed:1.5", "introduced:2.0", "fixed:2.1"));
    assertThat(suggest("1.2", a).target()).contains(v("1.5"));
  }

  @Test
  void movesToTheNextMajorWhenTheCurrentOneHasNoFix() {
    UpgradeSuggestion s = suggest("4.5.13", advisory("A", range("introduced:0", "fixed:5.1.2")));
    assertThat(s.kind()).isEqualTo(UpgradeSuggestion.Kind.NEXT_MAJOR);
    assertThat(s.target()).contains(v("5.1.2"));
    assertThat(s.explanation())
        .contains("No safe version is recorded in 4.x")
        .contains("major upgrade to 5.x");
    assertThat(s.shortText()).isEqualTo("5.1.2 (major)");
  }

  @Test
  void sameMajorFixThatIsStillAffectedForcesTheNextMajor() {
    UpgradeSuggestion s =
        suggest(
            "3.1",
            advisory("A", range("introduced:3.0", "fixed:3.2")),
            advisory("B", range("introduced:3.2", "fixed:4.0")));
    assertThat(s.kind()).isEqualTo(UpgradeSuggestion.Kind.NEXT_MAJOR);
    assertThat(s.target()).contains(v("4.0"));
  }

  @Test
  void noSafeVersionWhenOnlyLastAffectedIsKnown() {
    UpgradeSuggestion s =
        suggest("1.30", advisory("A", range("introduced:0", "last_affected:1.33")));
    assertThat(s.kind()).isEqualTo(UpgradeSuggestion.Kind.NONE_KNOWN);
    assertThat(s.target()).isEmpty();
    assertThat(s.explanation())
        .contains("up to and including 1.33")
        .contains("none is named offline");
    assertThat(s.shortText()).isEqualTo("none known");
  }

  @Test
  void noSafeVersionWhenOnlyAffectedVersionsAreListed() {
    UpgradeSuggestion s =
        suggest("1.9", advisory("A", PKG, List.of(), List.of("1.9", "1.10"), null));
    assertThat(s.kind()).isEqualTo(UpgradeSuggestion.Kind.NONE_KNOWN);
    assertThat(s.explanation()).contains("lists affected versions only");
  }

  @Test
  void noSafeVersionWhenEveryFixIsAffectedByAnUnboundedAdvisory() {
    UpgradeSuggestion s =
        suggest(
            "1.0",
            advisory("A", range("introduced:1.0", "fixed:1.1")),
            advisory("B", range("introduced:0")));
    assertThat(s.kind()).isEqualTo(UpgradeSuggestion.Kind.NONE_KNOWN);
    assertThat(s.explanation())
        .contains("1.1 (still affected by B)")
        .contains("B has no upper bound");
  }

  @Test
  void withdrawnAdvisoriesDoNotBlockAFix() {
    Advisory withdrawn =
        advisory("W", PKG, List.of(range("introduced:0")), List.of(), "2026-01-01T00:00:00Z");
    UpgradeSuggestion s =
        suggest("1.0", advisory("A", range("introduced:1.0", "fixed:1.1")), withdrawn);
    assertThat(s.target()).contains(v("1.1"));
  }

  @Test
  void preReleaseFixesAreLabelled() {
    UpgradeSuggestion s =
        suggest("1.0-beta1", advisory("A", range("introduced:0.9", "fixed:1.0-rc1")));
    assertThat(s.target()).contains(v("1.0-rc1"));
    assertThat(s.explanation()).contains("(a pre-release)");
  }
}
