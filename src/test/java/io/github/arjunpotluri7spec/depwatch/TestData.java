package io.github.arjunpotluri7spec.depwatch;

import io.github.arjunpotluri7spec.depwatch.advisory.Advisory;
import io.github.arjunpotluri7spec.depwatch.advisory.AffectedPackage;
import io.github.arjunpotluri7spec.depwatch.advisory.OsvRange;
import io.github.arjunpotluri7spec.depwatch.advisory.RangeEvent;
import io.github.arjunpotluri7spec.depwatch.model.Coordinate;
import io.github.arjunpotluri7spec.depwatch.model.Severity;
import io.github.arjunpotluri7spec.depwatch.version.MavenVersion;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** Builders for fictional test data. */
public final class TestData {

  public static final Path SAMPLES = Path.of("samples");
  public static final Path SAMPLE_DB = SAMPLES.resolve("osv-db");
  public static final Coordinate PKG = new Coordinate("com.example", "demo");

  private TestData() {}

  /** Events written as "introduced:1.0", "fixed:2.0", "last_affected:3", "limit:4". */
  public static OsvRange range(String... events) {
    List<RangeEvent> out = new ArrayList<>();
    for (String e : events) {
      int colon = e.indexOf(':');
      out.add(
          RangeEvent.of(RangeEvent.Kind.fromKey(e.substring(0, colon)), e.substring(colon + 1)));
    }
    return new OsvRange("ECOSYSTEM", out);
  }

  public static Advisory advisory(String id, OsvRange... ranges) {
    return advisory(id, PKG, List.of(ranges), List.of(), null);
  }

  public static Advisory advisory(
      String id, Coordinate pkg, List<OsvRange> ranges, List<String> versions, String withdrawn) {
    return new Advisory(
        id,
        List.of(),
        "Fictional advisory " + id,
        "",
        Severity.HIGH,
        "test",
        null,
        "2026-01-01T00:00:00Z",
        withdrawn,
        List.of(
            new AffectedPackage(pkg, ranges, versions.stream().map(MavenVersion::parse).toList())),
        List.of(),
        "test.json");
  }

  public static MavenVersion v(String s) {
    return MavenVersion.parse(s);
  }
}
