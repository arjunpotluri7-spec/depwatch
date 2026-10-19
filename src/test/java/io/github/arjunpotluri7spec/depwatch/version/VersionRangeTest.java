package io.github.arjunpotluri7spec.depwatch.version;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Range parsing and containment. The first group of rows are the examples in the Maven POM
 * reference, "Dependency Version Requirement Specification"
 * (https://maven.apache.org/pom.html#dependency-version-requirement-specification).
 */
class VersionRangeTest {

  @ParameterizedTest(name = "{1} in {0} = {2}")
  @CsvSource(
      delimiter = ';',
      value = {
        // [1.0]: x == 1.0
        "[1.0]; 1.0; true",
        "[1.0]; 1.0.0; true",
        "[1.0]; 1.0.1; false",
        "[1.0]; 0.9; false",
        // (,1.0]: x <= 1.0
        "(,1.0]; 0.1; true",
        "(,1.0]; 1.0; true",
        "(,1.0]; 1.0-sp; false",
        // [1.2,1.3]: 1.2 <= x <= 1.3
        "[1.2,1.3]; 1.2; true",
        "[1.2,1.3]; 1.2.5; true",
        "[1.2,1.3]; 1.3; true",
        "[1.2,1.3]; 1.3.1; false",
        "[1.2,1.3]; 1.1; false",
        // [1.0,2.0): 1.0 <= x < 2.0
        "[1.0,2.0); 1.0; true",
        "[1.0,2.0); 1.9.9; true",
        "[1.0,2.0); 2.0; false",
        // Documented surprise: 2.0-rc1 < 2.0, so it is inside [1.0,2.0)
        "[1.0,2.0); 2.0-rc1; true",
        "[1.0,2.0); 2.0-SNAPSHOT; true",
        // [1.5,): x >= 1.5
        "[1.5,); 1.5; true",
        "[1.5,); 99; true",
        "[1.5,); 1.4; false",
        // (,1.0],[1.2,): x <= 1.0 or x >= 1.2
        "(,1.0],[1.2,); 1.0; true",
        "(,1.0],[1.2,); 1.1; false",
        "(,1.0],[1.2,); 1.2; true",
        // (,1.1),(1.1,): everything except 1.1
        "(,1.1),(1.1,); 1.1; false",
        "(,1.1),(1.1,); 1.1.0; false",
        "(,1.1),(1.1,); 1.0; true",
        "(,1.1),(1.1,); 1.2; true",
        // Unions and exclusive bounds
        "[1,2),[3,4); 1.5; true",
        "[1,2),[3,4); 2; false",
        "[1,2),[3,4); 2.5; false",
        "[1,2),[3,4); 3; true",
        "[1,2),[3,4); 4; false",
        "(1.0,2.0]; 1.0; false",
        "(1.0,2.0]; 2.0; true",
        "[2.0-beta9,2.15.0); 2.14.1; true",
        "[2.0-beta9,2.15.0); 2.0-beta8; false",
        "[2.0-beta9,2.15.0); 2.15.0; false",
        "[1.0,2.0) , [3.0,); 3.5; true",
        "[,]; 7; true",
        "[1,2],[2,3]; 2; true"
      })
  void containment(String spec, String version, boolean expected) {
    VersionRange r = VersionRange.parse(spec);
    assertThat(r.contains(MavenVersion.parse(version))).isEqualTo(expected);
    assertThat(r.matchingRestriction(MavenVersion.parse(version)).isPresent()).isEqualTo(expected);
  }

  @Test
  void softRequirementMatchesEverything() {
    VersionRange r = VersionRange.parse("1.0");
    assertThat(r.isSoftRequirement()).isTrue();
    assertThat(r.recommendedVersion()).contains(MavenVersion.parse("1.0"));
    assertThat(r.contains(MavenVersion.parse("5.0"))).isTrue();
    assertThat(r.restrictions()).isEmpty();
  }

  @Test
  void restrictionsAreExposedInOrder() {
    VersionRange r = VersionRange.parse("(,1.0],[1.2,)");
    assertThat(r.restrictions()).hasSize(2);
    VersionRange.Restriction first = r.restrictions().get(0);
    assertThat(first.lower()).isNull();
    assertThat(first.upper()).isEqualTo(MavenVersion.parse("1.0"));
    assertThat(first.upperInclusive()).isTrue();
    assertThat(r).hasToString("(,1.0],[1.2,)");
    assertThat(VersionRange.parse("[1.0]").restrictions().get(0)).hasToString("[1.0]");
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "(1.0)", // a single version must use []
        "[1.0", // unclosed
        "[2.0,1.0]", // lower above upper
        "[1.0,1.0)", // empty
        "[1,3),[2,4)", // overlapping sets
        "[1.0,2.0),3.0", // trailing bare version
        "[1.0,2.0),", // trailing comma
        "[1,2,3]", // more than one comma
        "[]", // empty set
        "[1.0,)[2.0,3.0]", // set after an unbounded one
        "1.0]", // stray bracket
        " ",
      })
  void rejectsInvalidRanges(String spec) {
    assertThatThrownBy(() -> VersionRange.parse(spec)).isInstanceOf(InvalidVersionException.class);
  }

  @Test
  void errorMessagesNameTheProblem() {
    assertThatThrownBy(() -> VersionRange.parse("(1.0)"))
        .hasMessageContaining("single version must be written as [1.0]");
    assertThatThrownBy(() -> VersionRange.parse("[1,3),[2,4)")).hasMessageContaining("overlapping");
    assertThatThrownBy(() -> VersionRange.parse("[1.0,a b]")).hasMessageContaining("whitespace");
  }
}
