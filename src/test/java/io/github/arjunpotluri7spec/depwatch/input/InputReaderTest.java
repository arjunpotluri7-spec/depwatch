package io.github.arjunpotluri7spec.depwatch.input;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.arjunpotluri7spec.depwatch.TestData;
import io.github.arjunpotluri7spec.depwatch.util.DepwatchException;
import io.github.arjunpotluri7spec.depwatch.util.Limits;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class InputReaderTest {

  @TempDir Path dir;

  private static InputFormat detect(String name, String content) {
    return InputReader.detect(Path.of(name), content.getBytes(StandardCharsets.UTF_8));
  }

  @Test
  void detectsByFileName() {
    assertThat(detect("pom.xml", "")).isEqualTo(InputFormat.MAVEN_POM);
    assertThat(detect("lib-1.0.pom", "")).isEqualTo(InputFormat.MAVEN_POM);
    assertThat(detect("gradle.lockfile", "")).isEqualTo(InputFormat.GRADLE_LOCKFILE);
    assertThat(detect("buildscript-gradle.lockfile", "")).isEqualTo(InputFormat.GRADLE_LOCKFILE);
    assertThat(detect("app.cdx.json", "")).isEqualTo(InputFormat.CYCLONEDX_JSON);
    assertThat(detect("bom.json", "")).isEqualTo(InputFormat.CYCLONEDX_JSON);
  }

  @Test
  void detectsByContent() {
    assertThat(detect("deps.xml", "<?xml version=\"1.0\"?>\n<project>"))
        .isEqualTo(InputFormat.MAVEN_POM);
    assertThat(detect("sbom.json", "{\n \"bomFormat\": \"CycloneDX\"}"))
        .isEqualTo(InputFormat.CYCLONEDX_JSON);
    assertThat(detect("locks.txt", "# c\ncom.example:a:1.0=runtimeClasspath\n"))
        .isEqualTo(InputFormat.GRADLE_LOCKFILE);
  }

  @Test
  void undetectableInputNamesTheOverride() {
    assertThatThrownBy(() -> detect("notes.txt", "hello"))
        .isInstanceOf(DepwatchException.class)
        .hasMessageContaining("--input-type");
  }

  @Test
  void overrideBeatsDetection() throws IOException {
    Path f = dir.resolve("pom.xml");
    Files.writeString(f, "com.example:a:1.0=runtimeClasspath\n");
    ParsedInput in =
        InputReader.read(f, Optional.of(InputFormat.GRADLE_LOCKFILE), Limits.defaults());
    assertThat(in.dependencies()).hasSize(1);
  }

  @Test
  void sizeLimitAndMissingFiles() throws IOException {
    Path f = dir.resolve("gradle.lockfile");
    Files.writeString(f, "x".repeat(5000));
    assertThatThrownBy(() -> InputReader.read(f, Optional.empty(), new Limits(1000, 10, false)))
        .hasMessageContaining("larger than the limit of 1000 bytes");
    assertThatThrownBy(
            () -> InputReader.read(dir.resolve("missing.xml"), Optional.empty(), Limits.defaults()))
        .hasMessageContaining("file not found");
    assertThatThrownBy(() -> InputReader.read(dir, Optional.empty(), Limits.defaults()))
        .hasMessageContaining("not a regular file");
  }

  @Test
  void invalidUtf8IsRejected() throws IOException {
    Path f = dir.resolve("gradle.lockfile");
    Files.write(f, new byte[] {'a', (byte) 0xC3, (byte) 0x28});
    assertThatThrownBy(() -> InputReader.read(f, Optional.empty(), Limits.defaults()))
        .hasMessageContaining("not valid UTF-8");
  }

  @Test
  void readsEverySample() {
    for (String s :
        new String[] {"maven-app/pom.xml", "gradle-app/gradle.lockfile", "sbom/app.cdx.json"}) {
      ParsedInput in =
          InputReader.read(TestData.SAMPLES.resolve(s), Optional.empty(), Limits.defaults());
      assertThat(in.dependencies()).as(s).isNotEmpty();
    }
  }
}
