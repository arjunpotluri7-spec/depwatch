package io.github.arjunpotluri7spec.depwatch.config;

import io.github.arjunpotluri7spec.depwatch.license.LicenseException;
import io.github.arjunpotluri7spec.depwatch.license.LicensePolicy;
import io.github.arjunpotluri7spec.depwatch.model.Coordinate;
import io.github.arjunpotluri7spec.depwatch.util.DepwatchException;
import io.github.arjunpotluri7spec.depwatch.util.Limits;
import io.github.arjunpotluri7spec.depwatch.util.SafeFiles;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Loads and validates the YAML configuration. Every error names the file, the key and what was
 * expected; unknown keys are errors so typos are not silently ignored.
 */
public final class ConfigLoader {

  private static final Set<String> TOP = Set.of("licenses", "exceptions", "suppressions");
  private static final Set<String> LICENSE_KEYS = Set.of("allowed", "review_required", "denied");
  private static final Set<String> EXCEPTION_KEYS = Set.of("package", "license", "reason");
  private static final Set<String> SUPPRESSION_KEYS = Set.of("advisory", "package", "reason");

  private ConfigLoader() {}

  public static DepwatchConfig load(Path path, Limits limits) {
    String file = path.toString();
    return parse(SafeFiles.readUtf8(path, limits.maxFileBytes()), file);
  }

  public static DepwatchConfig parse(String text, String file) {
    Object doc = SafeYaml.load(text, file);
    if (doc == null) {
      return DepwatchConfig.empty();
    }
    Map<String, Object> root = map(doc, file, "top level");
    checkKeys(root, TOP, file, "top level");

    Optional<LicensePolicy> policy = Optional.empty();
    List<LicenseException> exceptions = new ArrayList<>();
    if (root.containsKey("exceptions")) {
      int i = 0;
      for (Object o : list(root.get("exceptions"), file, "exceptions")) {
        String where = "exceptions[" + i++ + "]";
        Map<String, Object> m = map(o, file, where);
        checkKeys(m, EXCEPTION_KEYS, file, where);
        Coordinate c = coordinate(required(m, "package", file, where), file, where);
        String reason = optionalString(m, "reason", file, where);
        if (reason == null || reason.isBlank()) {
          throw new DepwatchException(
              file
                  + ": "
                  + where
                  + ".reason is required: every license exception must say why it exists");
        }
        exceptions.add(new LicenseException(c, optionalString(m, "license", file, where), reason));
      }
    }
    if (root.containsKey("licenses")) {
      Map<String, Object> lic = map(root.get("licenses"), file, "licenses");
      checkKeys(lic, LICENSE_KEYS, file, "licenses");
      try {
        policy =
            Optional.of(
                new LicensePolicy(
                    ids(lic, "allowed", file),
                    ids(lic, "review_required", file),
                    ids(lic, "denied", file),
                    exceptions));
      } catch (IllegalArgumentException e) {
        throw new DepwatchException(file + ": licenses: " + e.getMessage());
      }
    } else if (!exceptions.isEmpty()) {
      throw new DepwatchException(
          file + ": exceptions are set but there is no licenses section to apply them to");
    }

    List<Suppression> suppressions = new ArrayList<>();
    if (root.containsKey("suppressions")) {
      int i = 0;
      for (Object o : list(root.get("suppressions"), file, "suppressions")) {
        String where = "suppressions[" + i++ + "]";
        Map<String, Object> m = map(o, file, where);
        checkKeys(m, SUPPRESSION_KEYS, file, where);
        String id = required(m, "advisory", file, where);
        String pkg = optionalString(m, "package", file, where);
        String reason = optionalString(m, "reason", file, where);
        if (reason == null || reason.isBlank()) {
          throw new DepwatchException(
              file + ": " + where + ".reason is required: every suppression must say why");
        }
        suppressions.add(
            new Suppression(id, pkg == null ? null : coordinate(pkg, file, where), reason));
      }
    }
    return new DepwatchConfig(policy, suppressions);
  }

  /**
   * Loads a {@code --licenses} mapping: a YAML map from {@code group:artifact} or {@code
   * group:artifact:version} to an SPDX expression.
   */
  public static LicenseMap loadLicenseMap(Path path, Limits limits) {
    String file = path.toString();
    Object doc = SafeYaml.load(SafeFiles.readUtf8(path, limits.maxFileBytes()), file);
    if (doc == null) {
      return new LicenseMap(Map.of());
    }
    Map<String, Object> root = map(doc, file, "top level");
    Map<String, String> out = new LinkedHashMap<>();
    for (Map.Entry<String, Object> e : root.entrySet()) {
      String key = e.getKey();
      String[] parts = key.split(":", -1);
      if (parts.length < 2 || parts.length > 3) {
        throw new DepwatchException(
            file + ": key '" + key + "' must be group:artifact or group:artifact:version");
      }
      coordinate(parts[0] + ":" + parts[1], file, key);
      if (!(e.getValue() instanceof String s) || s.isBlank()) {
        throw new DepwatchException(file + ": " + key + " must map to an SPDX expression string");
      }
      out.put(key, s.trim());
    }
    return new LicenseMap(out);
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> map(Object o, String file, String where) {
    if (!(o instanceof Map<?, ?> m)) {
      throw new DepwatchException(file + ": " + where + " must be a mapping");
    }
    for (Object k : m.keySet()) {
      if (!(k instanceof String)) {
        throw new DepwatchException(file + ": " + where + " has a non-string key '" + k + "'");
      }
    }
    return (Map<String, Object>) m;
  }

  private static List<?> list(Object o, String file, String where) {
    if (!(o instanceof List<?> l)) {
      throw new DepwatchException(file + ": " + where + " must be a list");
    }
    return l;
  }

  private static void checkKeys(
      Map<String, Object> m, Set<String> allowed, String file, String where) {
    for (String k : m.keySet()) {
      if (!allowed.contains(k)) {
        throw new DepwatchException(
            file
                + ": "
                + where
                + ": unknown key '"
                + k
                + "' (expected one of "
                + new java.util.TreeSet<>(allowed)
                + ")");
      }
    }
  }

  private static String required(Map<String, Object> m, String key, String file, String where) {
    String v = optionalString(m, key, file, where);
    if (v == null || v.isBlank()) {
      throw new DepwatchException(file + ": " + where + "." + key + " is required");
    }
    return v;
  }

  private static String optionalString(
      Map<String, Object> m, String key, String file, String where) {
    Object v = m.get(key);
    if (v == null) {
      return null;
    }
    if (!(v instanceof String s)) {
      throw new DepwatchException(file + ": " + where + "." + key + " must be a string");
    }
    return s.trim();
  }

  private static Set<String> ids(Map<String, Object> lic, String key, String file) {
    Set<String> out = new LinkedHashSet<>();
    if (!lic.containsKey(key) || lic.get(key) == null) {
      return out;
    }
    for (Object o : list(lic.get(key), file, "licenses." + key)) {
      if (!(o instanceof String s) || s.isBlank() || s.contains(" ")) {
        throw new DepwatchException(
            file + ": licenses." + key + " must contain SPDX identifiers (found '" + o + "')");
      }
      out.add(s.trim());
    }
    return out;
  }

  private static Coordinate coordinate(String text, String file, String where) {
    try {
      return Coordinate.parse(text);
    } catch (IllegalArgumentException e) {
      throw new DepwatchException(file + ": " + where + ": " + e.getMessage());
    }
  }
}
