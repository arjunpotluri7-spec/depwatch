package io.github.arjunpotluri7spec.depwatch.license;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.arjunpotluri7spec.depwatch.model.Coordinate;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class LicensePolicyTest {

  private static final Coordinate PKG = Coordinate.parse("org.example:lib");

  private static LicensePolicy policy(LicenseException... exceptions) {
    return new LicensePolicy(
        Set.of("Apache-2.0", "MIT", "GPL-2.0-or-later"),
        Set.of("LGPL-2.1-only", "MPL-2.0"),
        Set.of("GPL-3.0-only", "AGPL-3.0-only"),
        List.of(exceptions));
  }

  @ParameterizedTest(name = "{0} -> {1}")
  @CsvSource(
      delimiter = ';',
      value = {
        "Apache-2.0; ALLOWED",
        "apache-2.0; ALLOWED",
        "GPL-3.0-only; DENIED",
        "LGPL-2.1-only; REVIEW",
        "WTFPL; UNKNOWN",
        "MIT OR GPL-3.0-only; ALLOWED",
        "MIT AND GPL-3.0-only; DENIED",
        "MIT AND MPL-2.0; REVIEW",
        "WTFPL OR MPL-2.0; REVIEW",
        "WTFPL AND MIT; UNKNOWN",
        "GPL-3.0-only OR WTFPL; UNKNOWN",
        "(MIT OR GPL-3.0-only) AND LGPL-2.1-only; REVIEW",
        "Apache-2.0 WITH LLVM-exception; ALLOWED",
        "GPL-2.0+; ALLOWED",
        "not a valid expression!; UNKNOWN"
      })
  void evaluation(String expression, LicenseVerdict.Status status) {
    assertThat(policy().evaluate(PKG, expression).status()).isEqualTo(status);
  }

  @Test
  void missingLicenseIsUnknown() {
    LicenseVerdict v = policy().evaluate(PKG, null);
    assertThat(v.status()).isEqualTo(LicenseVerdict.Status.UNKNOWN);
    assertThat(v.explanation()).contains("no license information");
  }

  @Test
  void explanationsNameTheDecidingLicenses() {
    LicenseVerdict v = policy().evaluate(PKG, "MIT OR GPL-3.0-only");
    assertThat(v.explanation())
        .isEqualTo(
            "MIT is on the allowed list, GPL-3.0-only is on the denied list, so 'MIT OR"
                + " GPL-3.0-only' is allowed");
  }

  @Test
  void licenseSpecificExceptionAppliesOnlyToThatLicenseAndPackage() {
    LicenseException ex = new LicenseException(PKG, "GPL-3.0-only", "internal tool only");
    LicensePolicy p = policy(ex);
    LicenseVerdict ok = p.evaluate(PKG, "GPL-3.0-only");
    assertThat(ok.status()).isEqualTo(LicenseVerdict.Status.ALLOWED);
    assertThat(ok.exception()).isEqualTo(ex);
    assertThat(ok.explanation()).contains("by exception: internal tool only");
    assertThat(p.evaluate(PKG, "AGPL-3.0-only").status()).isEqualTo(LicenseVerdict.Status.DENIED);
    assertThat(p.evaluate(Coordinate.parse("org.example:other"), "GPL-3.0-only").status())
        .isEqualTo(LicenseVerdict.Status.DENIED);
  }

  @Test
  void wholePackageExceptionAcceptsAnything() {
    LicensePolicy p = policy(new LicenseException(PKG, null, "vendored, legal approved"));
    assertThat(p.evaluate(PKG, "AGPL-3.0-only").status()).isEqualTo(LicenseVerdict.Status.ALLOWED);
    assertThat(p.evaluate(PKG, null).status()).isEqualTo(LicenseVerdict.Status.ALLOWED);
  }

  @Test
  void exceptionsRequireAReason() {
    assertThatThrownBy(() -> new LicenseException(PKG, "MIT", " "))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("has no reason");
    assertThatThrownBy(() -> new LicenseException(PKG, "MIT", null))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void aLicenseCannotBeOnTwoLists() {
    assertThatThrownBy(() -> new LicensePolicy(Set.of("MIT"), Set.of(), Set.of("mit"), List.of()))
        .hasMessageContaining("more than one list");
  }
}
