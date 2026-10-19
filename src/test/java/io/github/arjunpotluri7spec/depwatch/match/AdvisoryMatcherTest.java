package io.github.arjunpotluri7spec.depwatch.match;

import static io.github.arjunpotluri7spec.depwatch.TestData.PKG;
import static io.github.arjunpotluri7spec.depwatch.TestData.advisory;
import static io.github.arjunpotluri7spec.depwatch.TestData.range;
import static io.github.arjunpotluri7spec.depwatch.TestData.v;
import static org.assertj.core.api.Assertions.assertThat;

import io.github.arjunpotluri7spec.depwatch.TestData;
import io.github.arjunpotluri7spec.depwatch.advisory.Advisory;
import io.github.arjunpotluri7spec.depwatch.advisory.AdvisoryDatabase;
import io.github.arjunpotluri7spec.depwatch.advisory.OsvLoader;
import io.github.arjunpotluri7spec.depwatch.model.Coordinate;
import io.github.arjunpotluri7spec.depwatch.util.Limits;
import java.util.List;
import org.junit.jupiter.api.Test;

class AdvisoryMatcherTest {

  @Test
  void affectedReasonNamesIntervalAdvisoryAndEvents() {
    Advisory a = advisory("DEMO-1", range("introduced:2.0-beta9", "fixed:2.15.0"));
    Check c = AdvisoryMatcher.check(a, PKG, v("2.14.1"));
    assertThat(c.status()).isEqualTo(Check.Status.AFFECTED);
    assertThat(c.reason())
        .isEqualTo(
            "2.14.1 is in [2.0-beta9, 2.15.0) from DEMO-1 (introduced 2.0-beta9, fixed 2.15.0)");
    assertThat(c.matchedRange()).isEqualTo("[2.0-beta9, 2.15.0)");
  }

  @Test
  void notAffectedReasonListsTheIntervals() {
    Advisory a =
        advisory("DEMO-1", range("introduced:1.0", "fixed:1.5", "introduced:2.0", "fixed:2.5"));
    Check c = AdvisoryMatcher.check(a, PKG, v("1.7"));
    assertThat(c.status()).isEqualTo(Check.Status.NOT_AFFECTED);
    assertThat(c.reason())
        .isEqualTo("1.7 is not affected by DEMO-1: outside [1.0, 1.5) and [2.0, 2.5)");
  }

  @Test
  void versionsListMatchesByMavenEquality() {
    Advisory a = advisory("DEMO-2", PKG, List.of(), List.of("1.10"), null);
    Check exact = AdvisoryMatcher.check(a, PKG, v("1.10"));
    assertThat(exact.affected()).isTrue();
    assertThat(exact.reason()).isEqualTo("1.10 is listed as an affected version in DEMO-2");
    Check padded = AdvisoryMatcher.check(a, PKG, v("1.10.0"));
    assertThat(padded.affected()).isTrue();
    assertThat(padded.reason()).contains("as 1.10, equal under Maven ordering");
    Check other = AdvisoryMatcher.check(a, PKG, v("1.11"));
    assertThat(other.affected()).isFalse();
    assertThat(other.reason()).contains("not among its 1 listed version");
  }

  @Test
  void withdrawnAdvisoriesNeverMatchButSayWhatTheyWouldHaveDone() {
    Advisory a =
        advisory(
            "DEMO-3", PKG, List.of(range("introduced:1.0")), List.of(), "2026-02-01T00:00:00Z");
    Check c = AdvisoryMatcher.check(a, PKG, v("1.5"));
    assertThat(c.status()).isEqualTo(Check.Status.WITHDRAWN);
    assertThat(c.affected()).isFalse();
    assertThat(c.reason()).contains("withdrawn on 2026-02-01").contains("would otherwise match");
  }

  @Test
  void otherPackagesAreNotMatched() {
    Advisory a = advisory("DEMO-4", range("introduced:0"));
    Check c = AdvisoryMatcher.check(a, new Coordinate("com.example", "other"), v("1.0"));
    assertThat(c.affected()).isFalse();
  }

  @Test
  void checkAllReturnsEveryAdvisoryForThePackage() {
    AdvisoryDatabase db = OsvLoader.load(TestData.SAMPLE_DB, Limits.defaults());
    Coordinate httpCore = Coordinate.parse("org.example:http-core");
    List<Check> checks = AdvisoryMatcher.checkAll(db, httpCore, v("4.5.13"));
    assertThat(checks)
        .extracting(c -> c.advisory().id() + "=" + c.status())
        .containsExactly("DEMO-2026-0005=AFFECTED", "DEMO-2026-0007=WITHDRAWN");
    assertThat(AdvisoryMatcher.affecting(db, httpCore, v("4.5.13"))).hasSize(1);
  }
}
