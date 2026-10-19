package io.github.arjunpotluri7spec.depwatch;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/** Keeps the library free of CLI concerns and of anything that could reach the network. */
class ArchitectureTest {

  private static final Path MAIN = Path.of("src/main/java/io/github/arjunpotluri7spec/depwatch");

  private static List<Path> librarySources() throws IOException {
    try (Stream<Path> s = Files.walk(MAIN)) {
      return s.filter(p -> p.toString().endsWith(".java"))
          .filter(p -> !p.startsWith(MAIN.resolve("cli")))
          .toList();
    }
  }

  @Test
  void libraryDoesNotDependOnTheCli() throws IOException {
    for (Path p : librarySources()) {
      String src = Files.readString(p);
      assertThat(src)
          .as(p.toString())
          .doesNotContain("import picocli")
          .doesNotContain(".depwatch.cli.");
    }
  }

  @Test
  void noNetworkOrProcessApisAnywhere() throws IOException {
    try (Stream<Path> s = Files.walk(MAIN)) {
      for (Path p : s.filter(x -> x.toString().endsWith(".java")).toList()) {
        String src = Files.readString(p);
        assertThat(src)
            .as(p.toString())
            .doesNotContain("java.net.URL")
            .doesNotContain("java.net.http")
            .doesNotContain("HttpURLConnection")
            .doesNotContain("java.net.Socket")
            .doesNotContain("ProcessBuilder")
            .doesNotContain("Runtime.getRuntime");
      }
    }
  }
}
