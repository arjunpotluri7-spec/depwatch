package io.github.arjunpotluri7spec.depwatch.input;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.arjunpotluri7spec.depwatch.TestData;
import io.github.arjunpotluri7spec.depwatch.model.Dependency;
import java.io.IOException;
import java.nio.file.Files;
import org.junit.jupiter.api.Test;

class GradleLockfileParserTest {

  @Test
  void parsesTheSampleLockfile() throws IOException {
    String text = Files.readString(TestData.SAMPLES.resolve("gradle-app/gradle.lockfile"));
    ParsedInput in = GradleLockfileParser.parse(text, "gradle.lockfile");
    assertThat(in.format()).isEqualTo(InputFormat.GRADLE_LOCKFILE);
    assertThat(in.dependencies()).hasSize(6);
    assertThat(in.diagnostics()).isEmpty();
    Dependency first = in.dependencies().get(0);
    assertThat(first.gav()).isEqualTo("com.example:jsonmapper:2.11.0");
    assertThat(first.location().line()).isEqualTo(5);
    assertThat(first.scope()).isEqualTo("compileClasspath,runtimeClasspath");
    assertThat(in.dependencies())
        .filteredOn(Dependency::dev)
        .extracting(Dependency::gav)
        .containsExactly("com.example:textutils:1.9");
  }

  @Test
  void malformedLinesAreCountedAndSkipped() {
    String text =
        String.join(
            "\n",
            "# comment",
            "",
            "com.example:a:1.0=runtimeClasspath",
            "not-a-coordinate",
            "com.example:b=runtimeClasspath",
            "com.example:c:1 0=runtimeClasspath",
            "com.example:d:e:f:2=runtimeClasspath",
            "empty=annotationProcessor",
            "com.example:e:2.0");
    ParsedInput in = GradleLockfileParser.parse(text, "gradle.lockfile");
    assertThat(in.dependencies())
        .extracting(Dependency::gav)
        .containsExactly("com.example:a:1.0", "com.example:e:2.0");
    assertThat(in.unusable()).isEqualTo(4);
    assertThat(in.diagnostics()).extracting(d -> d.line()).containsExactly(4, 5, 6, 7);
  }

  @Test
  void devDetectionRequiresEveryConfigurationToBeTest() {
    assertThat(GradleLockfileParser.isDevOnly("testCompileClasspath,testRuntimeClasspath"))
        .isTrue();
    assertThat(GradleLockfileParser.isDevOnly("integrationTestRuntimeClasspath")).isTrue();
    assertThat(GradleLockfileParser.isDevOnly("runtimeClasspath,testRuntimeClasspath")).isFalse();
    assertThat(GradleLockfileParser.isDevOnly("")).isFalse();
  }

  @Test
  void windowsLineEndingsAreAccepted() {
    ParsedInput in =
        GradleLockfileParser.parse("com.example:a:1.0=x\r\ncom.example:b:2.0=y\r\n", "l");
    assertThat(in.dependencies()).hasSize(2);
    assertThat(in.dependencies().get(1).location().line()).isEqualTo(2);
  }
}
