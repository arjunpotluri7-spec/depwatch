package io.github.arjunpotluri7spec.depwatch.config;

import io.github.arjunpotluri7spec.depwatch.util.DepwatchException;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import org.yaml.snakeyaml.error.MarkedYAMLException;
import org.yaml.snakeyaml.error.YAMLException;

/**
 * YAML loading with SnakeYAML's {@link SafeConstructor}: only maps, lists, strings, numbers,
 * booleans and null can be produced, never arbitrary Java objects. Duplicate keys, deep nesting and
 * alias expansion ("billion laughs") are limited.
 */
final class SafeYaml {

  private SafeYaml() {}

  static Object load(String text, String file) {
    LoaderOptions options = new LoaderOptions();
    options.setAllowDuplicateKeys(false);
    options.setMaxAliasesForCollections(10);
    options.setNestingDepthLimit(20);
    options.setCodePointLimit(Math.max(text.length() + 1, 1));
    options.setAllowRecursiveKeys(false);
    Yaml yaml = new Yaml(new SafeConstructor(options));
    try {
      return yaml.load(text);
    } catch (MarkedYAMLException e) {
      int line = e.getProblemMark() == null ? 0 : e.getProblemMark().getLine() + 1;
      throw new DepwatchException(
          file + (line > 0 ? ":" + line : "") + ": invalid YAML (" + e.getProblem() + ")", e);
    } catch (YAMLException e) {
      throw new DepwatchException(file + ": invalid YAML (" + firstLine(e.getMessage()) + ")", e);
    }
  }

  private static String firstLine(String s) {
    if (s == null) {
      return "unknown error";
    }
    int nl = s.indexOf('\n');
    return nl < 0 ? s : s.substring(0, nl);
  }
}
