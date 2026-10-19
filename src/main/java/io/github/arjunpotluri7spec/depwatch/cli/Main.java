package io.github.arjunpotluri7spec.depwatch.cli;

import io.github.arjunpotluri7spec.depwatch.util.DepwatchException;
import io.github.arjunpotluri7spec.depwatch.util.Text;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import picocli.CommandLine;

/** Entry point. Errors become one-line messages and exit code 2, never stack traces. */
public final class Main {

  private Main() {}

  public static void main(String[] args) {
    PrintWriter out = new PrintWriter(System.out, true, StandardCharsets.UTF_8);
    PrintWriter err = new PrintWriter(System.err, true, StandardCharsets.UTF_8);
    int code = run(args, out, err);
    out.flush();
    err.flush();
    System.exit(code);
  }

  /** Runs the CLI with the given streams and returns the exit code. */
  public static int run(String[] args, PrintWriter out, PrintWriter err) {
    CommandLine cl = new CommandLine(new DepwatchCommand());
    cl.setOut(out);
    cl.setErr(err);
    cl.setCaseInsensitiveEnumValuesAllowed(true);
    cl.setExecutionExceptionHandler(
        (ex, cmd, parseResult) -> {
          if (ex instanceof DepwatchException) {
            err.println("depwatch: error: " + Text.clean(ex.getMessage(), 2000));
          } else {
            err.println(
                "depwatch: error: unexpected internal error ("
                    + ex.getClass().getSimpleName()
                    + ": "
                    + Text.clean(String.valueOf(ex.getMessage()), 500)
                    + ")");
          }
          err.flush();
          return ExitCodes.ERROR;
        });
    cl.setParameterExceptionHandler(
        (ex, a) -> {
          err.println("depwatch: error: " + Text.clean(ex.getMessage(), 2000));
          err.println("Try '" + ex.getCommandLine().getCommandSpec().qualifiedName() + " --help'.");
          err.flush();
          return ExitCodes.ERROR;
        });
    return cl.execute(args);
  }
}
