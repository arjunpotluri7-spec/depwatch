package io.github.arjunpotluri7spec.depwatch.cli;

import io.github.arjunpotluri7spec.depwatch.util.DepwatchException;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Writes a report to stdout or to a file. Files are created with mode 0600 where the file system
 * supports POSIX permissions, an existing file is never replaced without {@code --force}, and a
 * symbolic link is never written through.
 */
final class OutputWriter {

  private OutputWriter() {}

  static void write(String content, Path output, boolean force, PrintWriter stdout) {
    if (output == null) {
      stdout.print(content);
      stdout.flush();
      return;
    }
    if (Files.isSymbolicLink(output)) {
      throw new DepwatchException(output + ": refusing to write through a symbolic link");
    }
    if (Files.exists(output, LinkOption.NOFOLLOW_LINKS)) {
      if (!force) {
        throw new DepwatchException(output + ": file exists (use --force to overwrite)");
      }
      if (!Files.isRegularFile(output, LinkOption.NOFOLLOW_LINKS)) {
        throw new DepwatchException(output + ": exists and is not a regular file");
      }
    }
    boolean posix = supportsPosix(output);
    List<OpenOption> opts = new ArrayList<>();
    opts.add(StandardOpenOption.WRITE);
    opts.add(LinkOption.NOFOLLOW_LINKS);
    if (force) {
      opts.add(StandardOpenOption.CREATE);
      opts.add(StandardOpenOption.TRUNCATE_EXISTING);
    } else {
      opts.add(StandardOpenOption.CREATE_NEW);
    }
    Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rw-------");
    try {
      if (posix && !Files.exists(output, LinkOption.NOFOLLOW_LINKS)) {
        FileAttribute<Set<PosixFilePermission>> attr = PosixFilePermissions.asFileAttribute(perms);
        Files.createFile(output, attr);
        opts.remove(StandardOpenOption.CREATE_NEW);
      }
      try (OutputStream out = Files.newOutputStream(output, opts.toArray(new OpenOption[0]))) {
        out.write(content.getBytes(StandardCharsets.UTF_8));
      }
      if (posix) {
        Files.setPosixFilePermissions(output, perms);
      }
    } catch (FileAlreadyExistsException e) {
      throw new DepwatchException(output + ": file exists (use --force to overwrite)", e);
    } catch (IOException e) {
      throw new DepwatchException(output + ": cannot write report (" + e.getMessage() + ")", e);
    }
  }

  private static boolean supportsPosix(Path output) {
    Path dir = output.toAbsolutePath().getParent();
    try {
      return dir != null && Files.getFileStore(dir).supportsFileAttributeView("posix");
    } catch (IOException e) {
      return false;
    }
  }
}
