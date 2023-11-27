package uk.msci.project.tests;

import static java.lang.Thread.sleep;
import static org.junit.Assert.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.testfx.api.FxAssert.verifyThat;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonType;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;
import javafx.stage.Window;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.testfx.api.FxRobot;
import org.testfx.framework.junit5.ApplicationExtension;
import org.testfx.framework.junit5.Start;
import org.testfx.matcher.control.LabeledMatchers;
import org.testfx.util.WaitForAsyncUtils;
import uk.msci.project.rsa.MainController;
import uk.msci.project.rsa.MainMenuView;

/**
 * Tests the key generation functionality of the Signature Scheme POC application. This includes
 * verifying the presence and correct behavior of UI components related to key generation, as well
 * as the validation and handling of user input and the successful export of generated keys.
 */
@ExtendWith(ApplicationExtension.class)
public class KeyGenFunctionalityTest {

  private MainMenuView mainMenuView;

  /**
   * Initialises the test fixture with the main stage.
   *
   * @param stage The primary stage for this application.
   * @throws Exception if initialization fails
   */
  @Start
  public void start(Stage stage) throws Exception {
    MainController mainController = new MainController(stage);

  }

  /**
   * Sets up the application's UI to the key generation view before each test.
   *
   * @param robot The robot used to simulate user interactions.
   */
  @BeforeEach
  public void setup(FxRobot robot) {
    robot.clickOn("#generateKeysButton");
    WaitForAsyncUtils.waitForFxEvents();
  }

  /**
   * Verifies that all necessary UI components for key generation are present.
   *
   * @param robot The robot used to simulate user interactions.
   */
  @Test
  void shouldContainKeyComponents(FxRobot robot) {
    WaitForAsyncUtils.waitForFxEvents();
    TextField keySizeTextField = (TextField) robot.lookup("#keySizeTextField").query();
    assertNotNull(keySizeTextField, "The component should exist.");
    Button generateButton = (Button) robot.lookup("#generateButton").query();
    assertNotNull(generateButton, "The component should exist.");
  }

  /**
   * Validates that the key size input field rejects invalid input and shows an appropriate error
   * message.
   *
   * @param robot The robot used to simulate user interactions.
   */
  @Test
  void shouldValidateKeySizeInput(FxRobot robot) {
    WaitForAsyncUtils.waitForFxEvents();
    TextField keySizeTextField = robot.lookup("#keySizeTextField").queryAs(TextField.class);
    // Input an invalid value
    robot.clickOn(keySizeTextField).write("invalid input");
    robot.clickOn("#generateButton");
    // Assert that the failure popup is visible
    assertTrue(robot.lookup("#failurePopup").queryAs(VBox.class).isVisible(),
        "Failure popup should be visible.");
  }

  /**
   * Ensures that valid input in the key size field results in a success message.
   *
   * @param robot The robot used to simulate user interactions.
   */
  @Test
  void shouldDisplaySuccessOnValidInput(FxRobot robot) {
    WaitForAsyncUtils.waitForFxEvents();
    TextField keySizeTextField = robot.lookup("#keySizeTextField").queryAs(TextField.class);
    // Input a valid value
    robot.clickOn(keySizeTextField).write("1024, 1024");
    robot.clickOn("#generateButton");
    // Assert that the success popup is visible
    assertTrue(robot.lookup("#successPopup").queryAs(VBox.class).isVisible(),
        "Success popup should be visible.");
  }

  /**
   * Tests the export functionality of the application to ensure that keys are saved to disk
   * correctly.
   *
   * @param robot The robot used to simulate user interactions.
   * @throws IOException          if there is an IO error during the export process.
   * @throws InterruptedException if the test is interrupted during execution.
   */
  @Test
  void shouldExportKeys(FxRobot robot) throws IOException, InterruptedException {
    WaitForAsyncUtils.waitForFxEvents();
    TextField keySizeTextField = robot.lookup("#keySizeTextField").queryAs(TextField.class);
    robot.clickOn(keySizeTextField).write("2048, 2048");
    robot.clickOn("#generateButton");
    // Now test the export functionality
    Button exportPrivateKeyButton = robot.lookup("#exportPrivateKeyButton").queryAs(Button.class);
    Button exportPublicKeyButton = robot.lookup("#exportPublicKeyButton").queryAs(Button.class);

    // Verify that buttons are visible and then simulate clicks
    assertTrue(exportPrivateKeyButton.isVisible(), "Export Private Key button should be visible.");
    assertTrue(exportPublicKeyButton.isVisible(), "Export Public Key button should be visible.");

    robot.clickOn(exportPrivateKeyButton);
    uk.msci.project.tests.MainTestUtility.clickOnDialogButton(robot, ButtonType.OK);
    robot.clickOn(exportPublicKeyButton);

    //logic to verify that the keys were actually exported by checking for existence of key files
    //if there are multiple key files then the files are exported with an increasing number suffix
    // getFile retrieves the most recently exported file i.e., the highest number suffix
    Optional<File> privateKeyFile = uk.msci.project.tests.MainTestUtility.getFile("key", ".rsa");
    assertTrue(privateKeyFile.isPresent(), "Expected exported file not found.");
    assertTrue(privateKeyFile.get().exists(), "Exported file should exist.");

    Optional<File> publicKeyFile = uk.msci.project.tests.MainTestUtility.getFile("publicKey", ".rsa");
    assertTrue(publicKeyFile.isPresent(), "Expected exported file not found.");
    assertTrue(publicKeyFile.get().exists(), "Exported file should exist.");
  }

  /**
   * Tests the application's error handling when less than the required amount of prime factors
   * inputted.
   *
   * @param robot The robot used to simulate user interactions.
   */
  @Test
  void shouldHandleErrorsDuringKeyGeneration(FxRobot robot) {
    WaitForAsyncUtils.waitForFxEvents();
    TextField keySizeTextField = robot.lookup("#keySizeTextField").queryAs(TextField.class);

    robot.clickOn(keySizeTextField).write("1024");
    robot.clickOn("#generateButton");
    // Assert that the failure popup is visible with the correct message
    VBox failurePopup = robot.lookup("#failurePopup").queryAs(VBox.class);
    assertTrue(failurePopup.isVisible(), "Failure popup should be visible.");
  }

  /**
   * Ensures that the key size input rejects special character input and displays an error message.
   *
   * @param robot The robot used to simulate user interactions.
   */
  @Test
  void shouldRejectSpecialCharactersInput(FxRobot robot) {
    WaitForAsyncUtils.waitForFxEvents();
    TextField keySizeTextField = robot.lookup("#keySizeTextField").queryAs(TextField.class);
    // Input a string of special characters
    robot.clickOn(keySizeTextField).write("!@#$%^&*()");
    robot.clickOn("#generateButton");
    // Assert that an error message is displayed indicating invalid input
    VBox failurePopup = robot.lookup("#failurePopup").queryAs(VBox.class);
    assertTrue(failurePopup.isVisible(),
        "Failure popup should be visible for special characters input.");
  }

  /**
   * Verifies that excessively long numeric input in the key size field is rejected with an error
   * message.
   *
   * @param robot The robot used to simulate user interactions.
   * @throws InterruptedException if the test is interrupted during execution.
   */
  @Test
  void shouldRejectExcessivelyLongNumberInput(FxRobot robot) throws InterruptedException {
    TextField keySizeTextField = robot.lookup("#keySizeTextField").queryAs(TextField.class);
    // Input a string of special characters
    robot.clickOn(keySizeTextField).write("11111111111111111111111111111111111111");
    robot.clickOn("#generateButton");
    // Assert that an error message is displayed indicating bit size is too long
    VBox failurePopup = robot.lookup("#failurePopup").queryAs(VBox.class);
    assertTrue(failurePopup.isVisible(),
        "Failure popup should be visible for excessively long number input.");

  }

  /**
   * Confirms that alphanumeric input in the key size field is rejected and an error message is
   * shown.
   *
   * @param robot The robot used to simulate user interactions.
   */
  @Test
  void shouldRejectAlphanumericInput(FxRobot robot) {
    TextField keySizeTextField = (TextField) robot.lookup("#keySizeTextField").query();
    // Input alphanumeric characters
    robot.clickOn(keySizeTextField).write("abc123");
    robot.clickOn("#generateButton");
    // Assert that an error message is displayed indicating only numeric values are valid
    VBox failurePopup = robot.lookup("#failurePopup").queryAs(VBox.class);
    assertTrue(failurePopup.isVisible(), "Failure popup should be visible for alphanumeric input.");
  }

  /**
   * Tests the functionality of navigating back to the main menu from the key generation view.
   *
   * @param robot The robot used to simulate user interactions.
   */
  @Test
  void shouldNavigateToMainMenu(FxRobot robot) {
    robot.clickOn("#backToMainMenuButton");
    WaitForAsyncUtils.waitForFxEvents();
    Button node = (Button) robot.lookup("#generateKeysButton").query();
    assertNotNull(node, "The component should exist.");
    // Verify that the button with the text "[K] Generate Keys" is present
    verifyThat("#generateKeysButton", LabeledMatchers.hasText("[K] Generate Keys"));

  }

}
