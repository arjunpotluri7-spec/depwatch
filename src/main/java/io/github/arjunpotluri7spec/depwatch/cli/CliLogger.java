package io.github.arjunpotluri7spec.depwatch.cli;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.arjunpotluri7spec.depwatch.model.Diagnostic;
import io.github.arjunpotluri7spec.depwatch.util.Json;
import io.github.arjunpotluri7spec.depwatch.util.Text;
import java.io.PrintWriter;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Locale;

/** Structured diagnostics on stderr, as text or one JSON object per line. */
public final class CliLogger {

  /** Severity levels for {@code --log-level}. */
  public enum Level {
    DEBUG,
    INFO,
    WARN,
    ERROR
  }

  /** {@code --log-format}. */
  public enum Format {
    TEXT,
    JSON
  }

  private final PrintWriter err;
  private final Level threshold;
  private final Format format;

  public CliLogger(PrintWriter err, Level threshold, Format format) {
    this.err = err;
    this.threshold = threshold;
    this.format = format;
  }

  public void debug(String msg) {
    log(Level.DEBUG, null, 0, msg);
  }

  public void info(String msg) {
    log(Level.INFO, null, 0, msg);
  }

  public void warn(String msg) {
    log(Level.WARN, null, 0, msg);
  }

  public void error(String msg) {
    log(Level.ERROR, null, 0, msg);
  }

  public void diagnostic(Diagnostic d) {
    Level l =
        switch (d.level()) {
          case INFO -> Level.INFO;
          case WARN -> Level.WARN;
          case ERROR -> Level.ERROR;
        };
    log(l, d.file(), d.line(), d.message());
  }

  public void log(Level level, String file, int line, String message) {
    if (level.compareTo(threshold) < 0) {
      return;
    }
    String msg = Text.clean(message, 2000);
    if (format == Format.JSON) {
      ObjectNode o = JsonNodeFactory.instance.objectNode();
      o.put("ts", Instant.now().truncatedTo(ChronoUnit.MILLIS).toString());
      o.put("level", level.name().toLowerCase(Locale.ROOT));
      o.put("logger", "depwatch");
      if (file != null) {
        o.put("file", file);
      }
      if (line > 0) {
        o.put("line", line);
      }
      o.put("msg", msg);
      try {
        err.println(
            Json.mapper()
                .writer()
                .without(SerializationFeature.INDENT_OUTPUT)
                .writeValueAsString(o));
      } catch (JsonProcessingException e) {
        err.println("{\"level\":\"error\",\"msg\":\"log serialization failed\"}");
      }
    } else {
      StringBuilder b =
          new StringBuilder("depwatch: ").append(level.name().toLowerCase(Locale.ROOT));
      b.append(": ");
      if (file != null) {
        b.append(file);
        if (line > 0) {
          b.append(':').append(line);
        }
        b.append(": ");
      }
      err.println(b.append(msg));
    }
    err.flush();
  }
}
