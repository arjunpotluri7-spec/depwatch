package io.github.arjunpotluri7spec.depwatch.advisory;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.arjunpotluri7spec.depwatch.model.Coordinate;
import io.github.arjunpotluri7spec.depwatch.model.Diagnostic;
import io.github.arjunpotluri7spec.depwatch.model.Severity;
import io.github.arjunpotluri7spec.depwatch.util.DepwatchException;
import io.github.arjunpotluri7spec.depwatch.util.Json;
import io.github.arjunpotluri7spec.depwatch.util.Limits;
import io.github.arjunpotluri7spec.depwatch.util.SafeFiles;
import io.github.arjunpotluri7spec.depwatch.version.InvalidVersionException;
import io.github.arjunpotluri7spec.depwatch.version.MavenVersion;
import java.io.IOException;
import java.nio.file.FileVisitOption;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Loads OSV advisory records (https://ossf.github.io/osv-schema/) from a directory of {@code
 * *.json} files. Each file holds one record or a JSON array of records. Malformed records are
 * skipped with a warning naming the file, the record and the problem; they never stop the load.
 *
 * <p>Only {@code affected[]} entries with ecosystem {@code Maven} are used. Nothing is fetched from
 * the network.
 */
public final class OsvLoader {

  private static final Pattern ID = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}");
  private static final int MAX_DEPTH = 16;

  private final Limits limits;
  private final List<Diagnostic> diagnostics = new ArrayList<>();
  private int skipped;
  private int nonMaven;
  private String currentLabel;

  public OsvLoader(Limits limits) {
    this.limits = limits;
  }

  /**
   * Loads every {@code *.json} file under {@code dir}.
   *
   * @throws DepwatchException if the directory is missing, unreadable, contains no JSON files, or
   *     has more files than the limit
   */
  public static AdvisoryDatabase load(Path dir, Limits limits) {
    return new OsvLoader(limits).loadDirectory(dir);
  }

  private AdvisoryDatabase loadDirectory(Path dir) {
    if (!Files.isDirectory(dir)) {
      throw new DepwatchException(dir + ": advisory database directory not found");
    }
    List<Path> files = listJsonFiles(dir);
    if (files.isEmpty()) {
      throw new DepwatchException(dir + ": no *.json advisory files found");
    }
    List<Advisory> loaded = new ArrayList<>();
    Set<String> seen = new HashSet<>();
    for (Path f : files) {
      String name = f.toString();
      JsonNode root;
      try {
        root = Json.parse(SafeFiles.readUtf8(f, limits.maxFileBytes()), name);
      } catch (DepwatchException e) {
        skipped++;
        diagnostics.add(Diagnostic.warn(null, e.getMessage() + "; file skipped"));
        continue;
      }
      List<JsonNode> records = new ArrayList<>();
      if (root.isArray()) {
        root.forEach(records::add);
      } else {
        records.add(root);
      }
      int index = 0;
      for (JsonNode rec : records) {
        String label = records.size() > 1 ? name + "[" + index + "]" : name;
        index++;
        Optional<Advisory> a = parseRecord(rec, label, name);
        if (a.isEmpty()) {
          continue;
        }
        if (!seen.add(a.get().id())) {
          skipped++;
          diagnostics.add(
              Diagnostic.warn(label, "duplicate advisory id " + a.get().id() + "; record skipped"));
          continue;
        }
        loaded.add(a.get());
      }
    }
    loaded.sort(Comparator.comparing(Advisory::id));
    return new AdvisoryDatabase(
        dir.toString(), loaded, diagnostics, files.size(), skipped, nonMaven);
  }

  private List<Path> listJsonFiles(Path dir) {
    List<Path> out = new ArrayList<>();
    Set<FileVisitOption> options =
        limits.followSymlinks() ? EnumSet.of(FileVisitOption.FOLLOW_LINKS) : Set.of();
    try {
      Files.walkFileTree(
          dir,
          options,
          MAX_DEPTH,
          new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
              if (attrs.isSymbolicLink()) {
                diagnostics.add(
                    Diagnostic.warn(
                        file.toString(),
                        "symbolic link not followed (use --follow-symlinks to allow)"));
                return FileVisitResult.CONTINUE;
              }
              if (attrs.isRegularFile()
                  && file.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".json")) {
                out.add(file);
                if (out.size() > limits.maxDbFiles()) {
                  throw new DepwatchException(
                      dir + ": more than " + limits.maxDbFiles() + " JSON files (limit)");
                }
              }
              return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFileFailed(Path file, IOException exc) {
              diagnostics.add(
                  Diagnostic.warn(file.toString(), "cannot read (" + exc.getMessage() + ")"));
              return FileVisitResult.CONTINUE;
            }
          });
    } catch (IOException e) {
      throw new DepwatchException(dir + ": cannot list directory (" + e.getMessage() + ")", e);
    }
    out.sort(Comparator.naturalOrder());
    return out;
  }

  /** Parses one record; on any problem records a warning and returns empty. */
  Optional<Advisory> parseRecord(JsonNode rec, String label, String sourceFile) {
    String id = "(no id)";
    currentLabel = label;
    try {
      if (!rec.isObject()) {
        throw new IllegalArgumentException("record is not a JSON object");
      }
      id = Json.text(rec, "id").orElseThrow(() -> new IllegalArgumentException("missing 'id'"));
      if (!ID.matcher(id).matches()) {
        throw new IllegalArgumentException("'id' has unexpected characters or length");
      }
      List<String> aliases = stringList(rec, "aliases");
      String summary = Json.text(rec, "summary").orElse("");
      String details = Json.text(rec, "details").orElse("");
      String published = Json.text(rec, "published").orElse(null);
      String modified = Json.text(rec, "modified").orElse(null);
      String withdrawn = Json.text(rec, "withdrawn").orElse(null);

      JsonNode affectedNode = rec.get("affected");
      List<AffectedPackage> affected = new ArrayList<>();
      boolean anyEntry = false;
      if (affectedNode != null && !affectedNode.isNull()) {
        if (!affectedNode.isArray()) {
          throw new IllegalArgumentException("'affected' must be an array");
        }
        int i = 0;
        for (JsonNode entry : affectedNode) {
          anyEntry = true;
          parseAffected(entry, "affected[" + i + "]").ifPresent(affected::add);
          i++;
        }
      }
      if (affected.isEmpty()) {
        if (anyEntry) {
          nonMaven++;
        } else {
          skipped++;
          diagnostics.add(
              Diagnostic.warn(label, "advisory " + id + " has no affected packages; skipped"));
        }
        return Optional.empty();
      }
      String[] severitySource = new String[1];
      Severity severity = severityOf(rec, severitySource);
      List<Reference> refs = new ArrayList<>();
      JsonNode refNode = rec.get("references");
      if (refNode != null && !refNode.isNull()) {
        if (!refNode.isArray()) {
          throw new IllegalArgumentException("'references' must be an array");
        }
        for (JsonNode r : refNode) {
          if (!r.isObject()) {
            throw new IllegalArgumentException("'references' entries must be objects");
          }
          Optional<String> url = Json.text(r, "url");
          url.ifPresent(u -> refs.add(new Reference(Json.text(r, "type").orElse("WEB"), u)));
        }
      }
      return Optional.of(
          new Advisory(
              id,
              aliases,
              summary,
              details,
              severity,
              severitySource[0],
              published,
              modified,
              withdrawn,
              affected,
              refs,
              sourceFile));
    } catch (IllegalArgumentException e) {
      skipped++;
      diagnostics.add(
          Diagnostic.warn(label, "malformed advisory " + id + ": " + e.getMessage() + "; skipped"));
      return Optional.empty();
    }
  }

  private Optional<AffectedPackage> parseAffected(JsonNode entry, String where) {
    if (!entry.isObject()) {
      throw new IllegalArgumentException(where + " is not an object");
    }
    JsonNode pkg = entry.get("package");
    if (pkg == null || !pkg.isObject()) {
      throw new IllegalArgumentException(where + ".package is missing");
    }
    String ecosystem = Json.text(pkg, "ecosystem").orElse("");
    if (!(ecosystem.equals("Maven") || ecosystem.startsWith("Maven:"))) {
      return Optional.empty();
    }
    String name =
        Json.text(pkg, "name")
            .orElseThrow(() -> new IllegalArgumentException(where + ".package.name is missing"));
    Coordinate coordinate;
    try {
      coordinate = Coordinate.parse(name);
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException(where + ".package.name: " + e.getMessage());
    }
    List<OsvRange> ranges = new ArrayList<>();
    JsonNode rangesNode = entry.get("ranges");
    if (rangesNode != null && !rangesNode.isNull()) {
      if (!rangesNode.isArray()) {
        throw new IllegalArgumentException(where + ".ranges must be an array");
      }
      int r = 0;
      for (JsonNode range : rangesNode) {
        parseRange(range, where + ".ranges[" + r + "]").ifPresent(ranges::add);
        r++;
      }
    }
    List<MavenVersion> versions = new ArrayList<>();
    for (String v : stringList(entry, "versions")) {
      versions.add(version(v, where + ".versions"));
    }
    if (ranges.isEmpty() && versions.isEmpty()) {
      throw new IllegalArgumentException(
          where + " has neither ECOSYSTEM ranges nor a versions list");
    }
    return Optional.of(new AffectedPackage(coordinate, ranges, versions));
  }

  private Optional<OsvRange> parseRange(JsonNode range, String where) {
    if (!range.isObject()) {
      throw new IllegalArgumentException(where + " is not an object");
    }
    String type =
        Json.text(range, "type")
            .orElseThrow(() -> new IllegalArgumentException(where + ".type is missing"));
    if (type.equals("GIT")) {
      return Optional.empty();
    }
    if (!type.equals("ECOSYSTEM")) {
      diagnostics.add(
          Diagnostic.warn(
              currentLabel,
              where
                  + ": range type "
                  + type
                  + " is not used for Maven (only ECOSYSTEM is); range ignored"));
      return Optional.empty();
    }
    JsonNode events = range.get("events");
    if (events == null || !events.isArray() || events.isEmpty()) {
      throw new IllegalArgumentException(where + ".events must be a non-empty array");
    }
    List<RangeEvent> out = new ArrayList<>();
    boolean introduced = false;
    int e = 0;
    for (JsonNode ev : events) {
      String at = where + ".events[" + e++ + "]";
      if (!ev.isObject() || ev.size() != 1) {
        throw new IllegalArgumentException(at + " must be an object with exactly one key");
      }
      Iterator<String> names = ev.fieldNames();
      String key = names.next();
      RangeEvent.Kind kind;
      try {
        kind = RangeEvent.Kind.fromKey(key);
      } catch (IllegalArgumentException ex) {
        throw new IllegalArgumentException(at + ": " + ex.getMessage());
      }
      JsonNode value = ev.get(key);
      if (!value.isTextual() || value.asText().isEmpty()) {
        throw new IllegalArgumentException(at + "." + key + " must be a non-empty string");
      }
      String raw = value.asText();
      if (kind == RangeEvent.Kind.LIMIT && raw.equals("*")) {
        continue;
      }
      if (kind == RangeEvent.Kind.INTRODUCED) {
        introduced = true;
      }
      try {
        out.add(RangeEvent.of(kind, raw));
      } catch (InvalidVersionException ex) {
        throw new IllegalArgumentException(at + "." + key + ": " + ex.getMessage());
      }
    }
    if (!introduced) {
      throw new IllegalArgumentException(where + " has no 'introduced' event");
    }
    return Optional.of(new OsvRange(type, out));
  }

  private static MavenVersion version(String raw, String where) {
    try {
      return MavenVersion.parse(raw);
    } catch (InvalidVersionException e) {
      throw new IllegalArgumentException(where + ": " + e.getMessage());
    }
  }

  private static List<String> stringList(JsonNode node, String field) {
    JsonNode v = node.get(field);
    if (v == null || v.isNull()) {
      return List.of();
    }
    if (!v.isArray()) {
      throw new IllegalArgumentException("'" + field + "' must be an array of strings");
    }
    List<String> out = new ArrayList<>();
    for (JsonNode s : v) {
      if (!s.isTextual()) {
        throw new IllegalArgumentException("'" + field + "' must contain only strings");
      }
      out.add(s.asText());
    }
    return out;
  }

  /**
   * Severity precedence: {@code database_specific.severity} when it is a known label (LOW,
   * MODERATE/MEDIUM, HIGH, CRITICAL); otherwise the highest CVSS v3.x base score in {@code
   * severity[]}, mapped with the CVSS v3.1 qualitative scale; otherwise unknown.
   */
  private Severity severityOf(JsonNode rec, String[] source) {
    JsonNode dbs = rec.get("database_specific");
    if (dbs != null && dbs.isObject()) {
      JsonNode label = dbs.get("severity");
      if (label != null && label.isTextual()) {
        Optional<Severity> s = Severity.fromLabel(label.asText());
        if (s.isPresent()) {
          source[0] = "database_specific.severity " + label.asText();
          return s.get();
        }
      }
    }
    JsonNode sev = rec.get("severity");
    Cvss3.Score best = null;
    boolean sawV4 = false;
    if (sev != null && sev.isArray()) {
      for (JsonNode s : sev) {
        if (!s.isObject()) {
          continue;
        }
        String type = Json.text(s, "type").orElse("");
        String score = Json.text(s, "score").orElse("");
        if (type.equals("CVSS_V3")) {
          try {
            Cvss3.Score parsed = Cvss3.score(score);
            if (best == null || parsed.baseScore() > best.baseScore()) {
              best = parsed;
            }
          } catch (IllegalArgumentException e) {
            diagnostics.add(
                Diagnostic.warn(
                    currentLabel, Json.text(rec, "id").orElse("?") + ": " + e.getMessage()));
          }
        } else if (type.equals("CVSS_V4")) {
          sawV4 = true;
        }
      }
    }
    if (best != null) {
      source[0] = best.vector() + " (base score " + best.baseScore() + ")";
      return best.severity();
    }
    source[0] =
        sawV4
            ? "CVSS v4 vector only (v4 scoring is not implemented); severity unknown"
            : "no severity in record";
    return Severity.UNKNOWN;
  }
}
