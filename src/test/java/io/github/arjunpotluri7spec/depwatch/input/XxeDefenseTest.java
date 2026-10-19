package io.github.arjunpotluri7spec.depwatch.input;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.arjunpotluri7spec.depwatch.util.DepwatchException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** XXE defense: DOCTYPEs are rejected, so no entity (internal or external) is ever expanded. */
class XxeDefenseTest {

  @TempDir Path dir;

  private static byte[] fixture(String name) throws IOException {
    try (InputStream in = XxeDefenseTest.class.getResourceAsStream("/xxe/" + name)) {
      return in.readAllBytes();
    }
  }

  @Test
  void externalEntityPomIsRejected() throws IOException {
    byte[] data = fixture("malicious-external-entity-pom.xml");
    assertThatThrownBy(() -> PomParser.parse(data, "malicious-pom.xml"))
        .isInstanceOf(DepwatchException.class)
        .hasMessageContaining("malicious-pom.xml")
        .hasMessageContaining("DOCTYPE declarations are not allowed (XXE protection)");
  }

  /** A canary file stands in for a secret: its content must never reach the parse result. */
  @Test
  void entityPointingAtALocalFileIsNeverRead() throws IOException {
    Path secret = dir.resolve("secret.txt");
    String canary = "CANARY-" + System.nanoTime();
    Files.writeString(secret, canary);
    String pom =
        "<?xml version=\"1.0\"?>\n<!DOCTYPE project [<!ENTITY s SYSTEM \""
            + secret.toUri()
            + "\">]>\n<project><groupId>org.example</groupId><artifactId>&s;</artifactId>"
            + "<version>1</version></project>";
    Throwable t =
        org.assertj.core.api.Assertions.catchThrowable(
            () -> PomParser.parse(pom.getBytes(StandardCharsets.UTF_8), "canary-pom.xml"));
    assertThat(t).isInstanceOf(DepwatchException.class);
    assertThat(t.getMessage()).doesNotContain(canary);
    assertThat(String.valueOf(t.getCause())).doesNotContain(canary);
  }

  @Test
  void billionLaughsIsRejected() throws IOException {
    byte[] data = fixture("billion-laughs-pom.xml");
    assertThatThrownBy(() -> PomParser.parse(data, "laughs.xml"))
        .isInstanceOf(DepwatchException.class)
        .hasMessageContaining("XXE protection");
  }

  @Test
  void externalDtdIsRejectedWithoutFetching() throws IOException {
    byte[] data = fixture("external-dtd-pom.xml");
    long start = System.nanoTime();
    assertThatThrownBy(() -> PomParser.parse(data, "dtd.xml"))
        .isInstanceOf(DepwatchException.class)
        .hasMessageContaining("XXE protection");
    // A fetch of the TEST-NET address would hang until a timeout; rejection is immediate.
    assertThat((System.nanoTime() - start) / 1_000_000).isLessThan(5_000);
  }

  @Test
  void xincludeIsNotProcessed() throws IOException {
    ParsedInput in = PomParser.parse(fixture("xinclude-pom.xml"), "xinclude.xml");
    assertThat(in.dependencies()).isEmpty();
    assertThat(in.diagnostics().toString()).doesNotContain("root:");
  }

  @Test
  void parserFactoryIsHardened() throws Exception {
    javax.xml.parsers.SAXParserFactory f = SecureXml.factory();
    assertThat(f.getFeature("http://apache.org/xml/features/disallow-doctype-decl")).isTrue();
    assertThat(f.getFeature("http://xml.org/sax/features/external-general-entities")).isFalse();
    assertThat(f.getFeature("http://xml.org/sax/features/external-parameter-entities")).isFalse();
    assertThat(f.isXIncludeAware()).isFalse();
  }

  @Test
  void deeplyNestedXmlIsRejected() {
    String deep = "<project>" + "<a>".repeat(100) + "</a>".repeat(100) + "</project>";
    assertThatThrownBy(() -> SecureXml.parse(deep.getBytes(StandardCharsets.UTF_8), "deep.xml"))
        .hasMessageContaining("nested deeper than");
  }

  @Test
  void malformedXmlReportsFileAndLine() {
    String bad = "<project>\n<dependencies>\n</project>";
    assertThatThrownBy(() -> PomParser.parse(bad.getBytes(StandardCharsets.UTF_8), "bad.xml"))
        .isInstanceOf(DepwatchException.class)
        .hasMessageStartingWith("bad.xml:3: invalid XML");
  }
}
