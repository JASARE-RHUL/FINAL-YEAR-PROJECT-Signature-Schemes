package uk.msci.project.rsa;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;

/**
 * Utility class for file handling, providing functionality to import from and export to files.
 */

public class FileHandle {

  /**
   * Imports content from a specified file.
   *
   * @param file The file from which to import content.
   * @return The string representation of the content.
   * @throws IOException If an I/O error occurs while reading the file.
   */
  public static String importFromFile(File file) throws IOException {
    if (!file.exists()) {
      throw new IOException("File does not exist: " + file);
    }

    if (!file.isFile()) {
      throw new IllegalArgumentException("File should not be a directory: " + file);
    }

    StringBuilder content = new StringBuilder();
    try (FileInputStream fis = new FileInputStream(file);
        InputStreamReader isr = new InputStreamReader(fis, StandardCharsets.UTF_8);
        BufferedReader br = new BufferedReader(isr)) {

      String line;
      while ((line = br.readLine()) != null) {
        content.append(line);
      }
    }
    return content.toString();
  }

  /**
   * Exports content to a file with a specified file name. If a file with the same name already
   * exists, a number suffix will be added to the file name to avoid overwriting the existing file.
   *
   * @param fileName The name of the file to which content should be exported.
   * @param content  The content to be written to the file.
   * @throws IOException If an I/O error occurs while writing to the file.
   */
  public static void exportToFile(String fileName, String content) throws IOException {
    File keyFile = new File(System.getProperty("user.dir"), fileName);
    keyFile = createUniqueFile(fileName);

    try (FileOutputStream fos = new FileOutputStream(keyFile);
        OutputStreamWriter osw = new OutputStreamWriter(fos, StandardCharsets.UTF_8);
        BufferedWriter bw = new BufferedWriter(osw)) {
      bw.write(content);
    }
  }
  static File createUniqueFile(String fileName) {
    File file = new File(System.getProperty("user.dir"), fileName);
    int count = 0;
    while (file.exists()) {
      count++;
      String newFileName = fileName.replaceFirst("^(.*?)(\\.[^.]*)?$", "$1_" + count + "$2");
      file = new File(System.getProperty("user.dir"), newFileName);
    }
    return file;
  }

}
