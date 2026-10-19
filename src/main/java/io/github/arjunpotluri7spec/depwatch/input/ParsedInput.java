package io.github.arjunpotluri7spec.depwatch.input;

import io.github.arjunpotluri7spec.depwatch.model.Dependency;
import io.github.arjunpotluri7spec.depwatch.model.Diagnostic;
import java.util.List;

/**
 * The dependencies read from one input file.
 *
 * @param file the path as the user gave it
 * @param unusable entries that were found but could not be used (unresolved version, malformed
 *     line, non-Maven component); each one also has a diagnostic
 * @param hasLicenseData true when the format carries license information (CycloneDX)
 */
public record ParsedInput(
    String file,
    InputFormat format,
    List<Dependency> dependencies,
    List<Diagnostic> diagnostics,
    int unusable,
    boolean hasLicenseData) {

  public ParsedInput {
    dependencies = List.copyOf(dependencies);
    diagnostics = List.copyOf(diagnostics);
  }
}
