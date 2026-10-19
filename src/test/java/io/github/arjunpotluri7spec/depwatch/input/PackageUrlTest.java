package io.github.arjunpotluri7spec.depwatch.input;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class PackageUrlTest {

  @Test
  void parsesMavenPurlWithQualifiersAndSubpath() {
    PackageUrl p =
        PackageUrl.parse("pkg:maven/com.example/logkit@2.14.1?type=jar&classifier=x#sub/path");
    assertThat(p).isEqualTo(new PackageUrl("maven", "com.example", "logkit", "2.14.1"));
  }

  @Test
  void percentDecodingAndCase() {
    PackageUrl p = PackageUrl.parse("PKG:Maven/org.ex%61mple/na%2Bme@1.0%2Bbuild");
    assertThat(p.type()).isEqualTo("maven");
    assertThat(p.namespace()).isEqualTo("org.example");
    assertThat(p.name()).isEqualTo("na+me");
    assertThat(p.version()).isEqualTo("1.0+build");
  }

  @Test
  void otherTypesAndMissingVersion() {
    PackageUrl npm = PackageUrl.parse("pkg:npm/%40scope/pkg@1.0.0");
    assertThat(npm.type()).isEqualTo("npm");
    assertThat(npm.namespace()).isEqualTo("@scope");
    assertThat(PackageUrl.parse("pkg:maven/g/a").version()).isEmpty();
  }

  @Test
  void rejectsMalformedPurls() {
    assertThatThrownBy(() -> PackageUrl.parse("maven/g/a@1")).hasMessageContaining("pkg:");
    assertThatThrownBy(() -> PackageUrl.parse("pkg:maven")).hasMessageContaining("no type/name");
    assertThatThrownBy(() -> PackageUrl.parse("pkg:maven/@1")).hasMessageContaining("empty name");
  }
}
