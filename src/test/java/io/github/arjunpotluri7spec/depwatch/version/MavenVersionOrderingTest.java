package io.github.arjunpotluri7spec.depwatch.version;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;

/**
 * Table-driven ordering tests. The table ({@code version-order-cases.csv}) cites its sources: the
 * Maven POM reference "Version Order Specification"
 * (https://maven.apache.org/pom.html#version-order-specification) and the ComparableVersion
 * javadoc.
 */
class MavenVersionOrderingTest {

  @ParameterizedTest(name = "{0} {1} {2}")
  @CsvFileSource(resources = "/version-order-cases.csv")
  void tableCase(String left, String relation, String right) {
    MavenVersion a = MavenVersion.parse(left);
    MavenVersion b = MavenVersion.parse(right);
    int expected =
        switch (relation) {
          case "<" -> -1;
          case "==" -> 0;
          case ">" -> 1;
          default -> throw new IllegalArgumentException("bad relation " + relation);
        };
    assertThat(a.compareTo(b)).as("%s vs %s", left, right).isEqualTo(expected);
    assertThat(b.compareTo(a)).as("antisymmetry %s vs %s", right, left).isEqualTo(-expected);
    if (expected == 0) {
      assertThat(a).isEqualTo(b);
      assertThat(a.hashCode()).isEqualTo(b.hashCode());
      assertThat(a.canonical()).isEqualTo(b.canonical());
    } else {
      assertThat(a).isNotEqualTo(b);
    }
  }

  @Test
  void tableHasAtLeastOneHundredCases() throws IOException {
    assertThat(rows()).hasSizeGreaterThanOrEqualTo(100);
  }

  /** The qualifier chain from the POM reference, as one ascending sequence. */
  @Test
  void documentedQualifierChainIsAscending() {
    List<String> chain =
        List.of(
            "1-alpha-1",
            "1-beta-1",
            "1-milestone-1",
            "1-rc-1",
            "1-snapshot",
            "1",
            "1-sp",
            "1-sp-1",
            "1-abc",
            "1-1",
            "1.1");
    assertAscending(chain);
  }

  /** Sorting a shuffled list must reproduce the known order exactly. */
  @Test
  void shuffledSortReproducesOrder() {
    List<String> ordered =
        List.of(
            "0.9",
            "1.0-alpha-1",
            "1.0-alpha-2",
            "1.0-beta-1",
            "1.0-M1",
            "1.0-rc1",
            "1.0-SNAPSHOT",
            "1.0",
            "1.0-sp1",
            "1.0-1",
            "1.0.1",
            "1.1",
            "1.9",
            "1.10",
            "2.0-beta9",
            "2.0",
            "2.9.10.8",
            "2.10.0",
            "2.10.5.1",
            "10");
    List<MavenVersion> shuffled =
        new ArrayList<>(ordered.stream().map(MavenVersion::parse).toList());
    Collections.shuffle(shuffled, new Random(7));
    Collections.sort(shuffled);
    assertThat(shuffled.stream().map(MavenVersion::original).toList()).isEqualTo(ordered);
  }

  /**
   * Maven's own ordering is not transitive for versions shaped like {@code 1-0.alpha}: since the
   * MNG-6964 change a trailing sub-list is compared element by element against padding, which gives
   * {@code 1 < 1-sp < 1-0.alpha < 1}. Checked against maven-artifact 3.9.16; Depwatch reproduces
   * Maven's answers rather than inventing a different order.
   */
  @Test
  void mavenNonTransitiveCaseIsReproduced() {
    MavenVersion one = MavenVersion.parse("1");
    MavenVersion sp = MavenVersion.parse("1-sp");
    MavenVersion odd = MavenVersion.parse("1-0.alpha");
    assertThat(one).isLessThan(sp);
    assertThat(sp).isLessThan(odd);
    assertThat(odd).isLessThan(one);
  }

  /**
   * compareTo must be transitive over every version in the table, except the {@code 1-0.x} shape
   * covered by {@link #mavenNonTransitiveCaseIsReproduced()}.
   */
  @Test
  void orderingIsTransitiveAcrossTableVersions() throws IOException {
    Set<String> distinct = new LinkedHashSet<>();
    for (String[] row : rows()) {
      distinct.add(row[0]);
      distinct.add(row[2]);
    }
    distinct.removeIf(s -> s.startsWith("1-0."));
    List<MavenVersion> all = distinct.stream().map(MavenVersion::parse).toList();
    for (MavenVersion a : all) {
      for (MavenVersion b : all) {
        if (a.compareTo(b) > 0) {
          continue;
        }
        for (MavenVersion c : all) {
          if (b.compareTo(c) <= 0) {
            assertThat(a.compareTo(c)).as("%s <= %s <= %s", a, b, c).isLessThanOrEqualTo(0);
          }
        }
      }
    }
  }

  private static void assertAscending(List<String> versions) {
    for (int i = 1; i < versions.size(); i++) {
      MavenVersion prev = MavenVersion.parse(versions.get(i - 1));
      MavenVersion next = MavenVersion.parse(versions.get(i));
      assertThat(prev).as("%s < %s", prev, next).isLessThan(next);
    }
  }

  private static List<String[]> rows() throws IOException {
    List<String[]> out = new ArrayList<>();
    try (InputStream in =
        MavenVersionOrderingTest.class.getResourceAsStream("/version-order-cases.csv")) {
      String text = new String(in.readAllBytes(), StandardCharsets.UTF_8);
      for (String line : text.split("\n")) {
        if (line.isBlank() || line.startsWith("#")) {
          continue;
        }
        String[] p = line.split(",");
        out.add(new String[] {p[0].trim(), p[1].trim(), p[2].trim()});
      }
    }
    return out;
  }
}
