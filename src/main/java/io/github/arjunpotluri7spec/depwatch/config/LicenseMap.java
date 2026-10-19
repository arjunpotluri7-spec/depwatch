package io.github.arjunpotluri7spec.depwatch.config;

import io.github.arjunpotluri7spec.depwatch.model.Dependency;
import java.util.Map;
import java.util.Optional;

/**
 * License expressions supplied with {@code --licenses} for inputs that carry none (POMs and
 * lockfiles). A {@code group:artifact:version} key wins over {@code group:artifact}.
 */
public record LicenseMap(Map<String, String> entries) {

  public LicenseMap {
    entries = Map.copyOf(entries);
  }

  public Optional<String> lookup(Dependency d) {
    String exact = entries.get(d.coordinate() + ":" + d.version().original());
    if (exact != null) {
      return Optional.of(exact);
    }
    return Optional.ofNullable(entries.get(d.coordinate().toString()));
  }
}
