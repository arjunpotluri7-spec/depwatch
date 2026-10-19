package io.github.arjunpotluri7spec.depwatch.input;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class PropertyResolverTest {

  @Test
  void expandsNestedPlaceholders() {
    PropertyResolver r = new PropertyResolver(Map.of("a", "1", "b", "${a}.2", "c", "v${b}-${a}"));
    PropertyResolver.Result res = r.resolve("${c}");
    assertThat(res.value()).isEqualTo("v1.2-1");
    assertThat(res.complete()).isTrue();
  }

  @Test
  void depthIsBounded() {
    Map<String, String> props = new HashMap<>();
    for (int i = 0; i < 20; i++) {
      props.put("p" + i, "${p" + (i + 1) + "}");
    }
    props.put("p20", "x");
    PropertyResolver.Result res = new PropertyResolver(props).resolve("${p0}");
    assertThat(res.complete()).isFalse();
    assertThat(res.problems()).anyMatch(p -> p.contains("nested deeper than 10"));
  }

  @Test
  void cyclesAreDetected() {
    PropertyResolver.Result res =
        new PropertyResolver(Map.of("a", "${b}", "b", "${c}", "c", "${a}")).resolve("${a}");
    assertThat(res.complete()).isFalse();
    assertThat(res.problems()).anyMatch(p -> p.contains("property cycle through ${a}"));
  }

  @Test
  void selfReferenceIsACycle() {
    PropertyResolver.Result res = new PropertyResolver(Map.of("a", "${a}")).resolve("${a}");
    assertThat(res.problems()).anyMatch(p -> p.contains("cycle"));
  }

  @Test
  void expansionBlowUpIsBounded() {
    Map<String, String> props = new HashMap<>();
    props.put("x0", "lol");
    for (int i = 1; i <= 9; i++) {
      String prev = "${x" + (i - 1) + "}";
      props.put("x" + i, prev.repeat(10));
    }
    PropertyResolver.Result res = new PropertyResolver(props).resolve("${x9}");
    assertThat(res.complete()).isFalse();
    assertThat(res.value().length()).isLessThanOrEqualTo(4096);
  }

  @Test
  void unterminatedAndUnknownPlaceholders() {
    PropertyResolver r = new PropertyResolver(Map.of());
    assertThat(r.resolve("${oops").problems()).anyMatch(p -> p.contains("unterminated"));
    assertThat(r.resolve("${missing}").value()).isEqualTo("${missing}");
    assertThat(r.resolve("plain").complete()).isTrue();
  }
}
