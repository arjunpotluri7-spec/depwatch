package io.github.arjunpotluri7spec.depwatch.license;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class SpdxExpressionTest {

  @Test
  void andBindsTighterThanOr() {
    SpdxExpression e = SpdxExpression.parse("MIT OR Apache-2.0 AND BSD-3-Clause");
    assertThat(e).isInstanceOf(SpdxExpression.Or.class);
    assertThat(e).hasToString("MIT OR (Apache-2.0 AND BSD-3-Clause)");
  }

  @Test
  void parenthesesWithAndCaseInsensitiveOperators() {
    SpdxExpression e =
        SpdxExpression.parse("(MIT or Apache-2.0) and GPL-2.0-only WITH Classpath-exception-2.0");
    assertThat(e).isInstanceOf(SpdxExpression.And.class);
    assertThat(e.licenseIds()).containsExactly("MIT", "Apache-2.0", "GPL-2.0-only");
    assertThat(e.toString()).contains("GPL-2.0-only WITH Classpath-exception-2.0");
  }

  @Test
  void plusAndLicenseRef() {
    assertThat(SpdxExpression.parse("GPL-2.0+").licenseIds()).containsExactly("GPL-2.0+");
    assertThat(SpdxExpression.parse("LicenseRef-Acme").licenseIds())
        .containsExactly("LicenseRef-Acme");
  }

  @ParameterizedTest
  @ValueSource(
      strings = {"", "MIT OR", "(MIT", "MIT)", "AND MIT", "MIT WITH", "MIT; rm", "MIT Apache-2.0"})
  void rejectsMalformedExpressions(String bad) {
    assertThatThrownBy(() -> SpdxExpression.parse(bad))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void deepNestingIsBounded() {
    String deep = "(".repeat(40) + "MIT" + ")".repeat(40);
    assertThatThrownBy(() -> SpdxExpression.parse(deep)).hasMessageContaining("nested too deeply");
  }
}
