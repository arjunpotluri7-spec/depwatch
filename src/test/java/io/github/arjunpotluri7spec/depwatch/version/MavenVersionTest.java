package io.github.arjunpotluri7spec.depwatch.version;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.math.BigInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

class MavenVersionTest {

  /** Canonical forms use Maven's notation: '.' between items, '-' before a sub-list. */
  @ParameterizedTest(name = "{0} -> {1}")
  @CsvSource({
    "1.0.0, 1",
    "1.0, 1",
    "1-0, 1",
    "1.0-SNAPSHOT, 1-snapshot",
    "2.0-rc1, 2-rc-1",
    "1.0alpha1, 1-alpha-1",
    "1.0.0.RC1, 1-rc-1",
    "1-1.foo-bar1baz-.1, 1-1.foo-bar-1-baz-0.1",
    "1.ga, 1",
    "1.0.0-foo.0.0, 1-foo",
    "2.10.5.1, 2.10.5.1",
    "1.01, 1.1",
    "1.0.Final, 1"
  })
  void canonicalForm(String input, String canonical) {
    assertThat(MavenVersion.parse(input).canonical()).isEqualTo(canonical);
  }

  @Test
  void originalTextIsKept() {
    MavenVersion v = MavenVersion.parse("1.0.0-SNAPSHOT");
    assertThat(v.original()).isEqualTo("1.0.0-SNAPSHOT");
    assertThat(v).hasToString("1.0.0-SNAPSHOT");
  }

  @ParameterizedTest
  @ValueSource(
      strings = {"", " 1.0", "1.0 ", "1 0", "1.0\t", "[1.0]", "(1.0", "1,0", "1.0)", "a\u0007"})
  void rejectsInvalidStrings(String bad) {
    assertThatThrownBy(() -> MavenVersion.parse(bad)).isInstanceOf(InvalidVersionException.class);
    assertThat(MavenVersion.tryParse(bad)).isEmpty();
  }

  @Test
  void rejectsNullAndOverlongStrings() {
    assertThatThrownBy(() -> MavenVersion.parse(null))
        .isInstanceOf(InvalidVersionException.class)
        .hasMessageContaining("missing");
    String longVersion = "1.".repeat(200) + "1";
    assertThatThrownBy(() -> MavenVersion.parse(longVersion))
        .isInstanceOf(InvalidVersionException.class)
        .hasMessageContaining("longer than 256");
  }

  @Test
  void majorVersion() {
    assertThat(MavenVersion.parse("2.0-beta9").major()).contains(BigInteger.TWO);
    assertThat(MavenVersion.parse("10.1").major()).contains(BigInteger.TEN);
    assertThat(MavenVersion.parse("0").major()).contains(BigInteger.ZERO);
    assertThat(MavenVersion.parse("alpha").major()).isEmpty();
  }

  @Test
  void preReleaseDetection() {
    assertThat(MavenVersion.parse("1.0-rc1").isPreRelease()).isTrue();
    assertThat(MavenVersion.parse("1.0-SNAPSHOT").isPreRelease()).isTrue();
    assertThat(MavenVersion.parse("1.0-M2").isPreRelease()).isTrue();
    assertThat(MavenVersion.parse("1.0").isPreRelease()).isFalse();
    assertThat(MavenVersion.parse("1.0-sp1").isPreRelease()).isFalse();
    assertThat(MavenVersion.parse("1.0.Final").isPreRelease()).isFalse();
  }

  @Test
  void hugeNumbersCompareByValue() {
    MavenVersion a = MavenVersion.parse("1." + "9".repeat(40));
    MavenVersion b = MavenVersion.parse("1.1" + "0".repeat(40));
    assertThat(a).isLessThan(b);
  }
}
