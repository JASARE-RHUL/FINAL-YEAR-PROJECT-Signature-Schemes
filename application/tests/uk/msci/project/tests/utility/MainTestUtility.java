package uk.msci.project.tests;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javafx.scene.Node;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonType;
import org.testfx.api.FxRobot;
import org.testfx.util.WaitForAsyncUtils;

/**
 * A utility class for common test functions used across different test classes. This class provides
 * methods to handle file operations and user interface interactions that are reused in multiple
 * tests.
 */
public class MainTestUtility {

  /**
   * Retrieves the most recently created file based on a specified base name and extension. It
   * assumes that if multiple files exist, they are suffixed with an increasing numeric value.
   *
   * @param fileBaseName  The base name of the file to search for.
   * @param fileExtension The extension of the file.
   * @return An {@code Optional<File>} which contains the file if found.
   * @throws IOException if an I/O error occurs when accessing the file system.
   */
  protected static Optional<File> getFile(String fileBaseName, String fileExtension)
      throws IOException {
    Pattern filePattern = Pattern.compile(
        Pattern.quote(fileBaseName) + "(?:_(\\d+))?" + Pattern.quote(fileExtension) + "$");
    // Resolve the path to the user's current working directory
    File currentDirectory = new File(System.getProperty("user.dir"));

    // Find the most recent file, considering possible numeric suffixes
    Optional<File> mostRecentFile = Files.list(currentDirectory.toPath())
        .map(Path::toFile)
        .filter(f -> filePattern.matcher(f.getName()).matches())
        .max(Comparator.comparingInt(f -> {
          Matcher matcher = filePattern.matcher(f.getName());
          if (matcher.matches() && matcher.group(1) != null) {
            return Integer.parseInt(matcher.group(1));
          }
          return 0; // No numeric suffix means it's the base file
        }));
    return mostRecentFile;
  }

  /**
   * Clicks on a dialog button with the specified {@code ButtonType}. This method will wait for the
   * button to become available in the UI before clicking.
   *
   * @param robot      The robot used to simulate user interactions.
   * @param buttonType The type of button to click on in the dialog.
   */
  protected static void clickOnDialogButton(FxRobot robot, ButtonType buttonType) {
    // Wait until the alert is shown and the button becomes available
    WaitForAsyncUtils.waitForFxEvents();
    // Find and click the button in the alert dialog
    robot.clickOn((Node) robot.lookup(button -> button instanceof Button &&
        ((Button) button).getText().equals(buttonType.getText())).tryQuery().orElseThrow(
        () -> new AssertionError("Button with text '" + buttonType.getText() + "' not found.")
    ));
  }
}
