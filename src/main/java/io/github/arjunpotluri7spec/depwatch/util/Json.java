package io.github.arjunpotluri7spec.depwatch.util;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import java.util.Optional;

/** One place for JSON settings: strict, bounded parsing and stable, pretty output. */
public final class Json {

  private static final ObjectMapper MAPPER = build();

  private Json() {}

  private static ObjectMapper build() {
    JsonFactory factory =
        JsonFactory.builder()
            .streamReadConstraints(
                StreamReadConstraints.builder()
                    .maxNestingDepth(64)
                    .maxStringLength(4_000_000)
                    .maxNumberLength(64)
                    .build())
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .build();
    return JsonMapper.builder(factory)
        .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
        .disable(JsonParser.Feature.AUTO_CLOSE_SOURCE)
        .enable(SerializationFeature.INDENT_OUTPUT)
        .build();
  }

  public static ObjectMapper mapper() {
    return MAPPER;
  }

  /**
   * Parses JSON text.
   *
   * @throws DepwatchException with the file name, line and column of the syntax error
   */
  public static JsonNode parse(String text, String fileName) {
    try {
      return MAPPER.readTree(text);
    } catch (JsonProcessingException e) {
      String where = "";
      if (e.getLocation() != null && e.getLocation().getLineNr() > 0) {
        where = ":" + e.getLocation().getLineNr();
      }
      throw new DepwatchException(
          fileName + where + ": invalid JSON (" + e.getOriginalMessage() + ")", e);
    }
  }

  /** The text of a string field, or empty when it is absent or JSON null. */
  public static Optional<String> text(JsonNode node, String field) {
    JsonNode v = node.get(field);
    if (v == null || v.isNull()) {
      return Optional.empty();
    }
    if (!v.isTextual()) {
      throw new IllegalArgumentException("'" + field + "' must be a string");
    }
    return Optional.of(v.asText());
  }
}
