package uk.msci.project.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.testfx.api.FxAssert.verifyThat;
import static uk.msci.project.tests.MainTestUtility.testFileExport;
import static uk.msci.project.tests.PublicKeyTest.deleteFilesWithSuffix;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.util.Optional;
import javafx.application.Platform;
import javafx.scene.Node;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonType;
import javafx.scene.control.ComboBox;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.layout.HBox;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.testfx.api.FxRobot;
import org.testfx.framework.junit5.ApplicationExtension;
import org.testfx.framework.junit5.Start;
import org.testfx.matcher.control.LabeledMatchers;
import org.testfx.service.query.EmptyNodeQueryException;
import org.testfx.util.WaitForAsyncUtils;
import uk.msci.project.rsa.FileHandle;
import uk.msci.project.rsa.GenModel;
import uk.msci.project.rsa.GenRSA;
import uk.msci.project.rsa.KeyPair;
import uk.msci.project.rsa.MainController;
import uk.msci.project.rsa.MainMenuView;
import uk.msci.project.rsa.PrivateKey;
import uk.msci.project.rsa.SignView;
import uk.msci.project.rsa.SignatureController;
import uk.msci.project.rsa.SignatureModel;
import uk.msci.project.rsa.SignatureType;

/**
 * This class contains tests for the signing functionality of the Signature Scheme POC application.
 * It includes tests for UI component existence, error handling in various scenarios such as missing
 * key or text, handling of different signature schemes, and the export functionality for signatures
 * and non-recoverable messages.
 */
@ExtendWith(ApplicationExtension.class)
public class SignFunctionalityTest {

  private MainController mainController;

  /**
   * Initializes the test fixture with the main stage.
   *
   * @param stage The primary stage for this application.
   * @throws Exception if initialization fails
   */
  @Start
  public void start(Stage stage) throws Exception {
    mainController = new MainController(stage);
  }

  /**
   * Sets up the application's UI to the key generation view before each test.
   *
   * @param robot The robot used to simulate user interactions.
   */
  @BeforeEach
  public void setup(FxRobot robot) {
    String fileNamePrefix = "testFile";
    String fileExtension = "txt";
    deleteFilesWithSuffix(fileNamePrefix, fileExtension);
    robot.clickOn("#signDocumentButton");
    WaitForAsyncUtils.waitForFxEvents();

  }

  /**
   * Verifies the presence of all necessary UI components within the sign view.
   *
   * @param robot The robot used to simulate user interactions.
   */
  @Test
  void shouldContainUIComponents(FxRobot robot) {
    assertNotNull(robot.lookup("#textInput").queryAs(TextArea.class),
        "Text input area should exist.");
    assertNotNull(robot.lookup("#importTextButton").queryAs(Button.class),
        "Import text button should exist.");
    assertNotNull(robot.lookup("#keyField").queryAs(TextField.class), "Key field should exist.");
    assertNotNull(robot.lookup("#importKeyButton").queryAs(Button.class),
        "Import key button should exist.");
    assertNotNull(robot.lookup("#signatureSchemeDropdown").queryAs(ComboBox.class),
        "Signature scheme dropdown should exist.");
    assertNotNull(robot.lookup("#createSignatureButton").queryAs(Button.class),
        "Create signature button should exist.");
  }

  /**
   * Tests the application's response when attempting to sign text without providing a key.
   *
   * @param robot The robot used to simulate user interactions.
   */
  @Test
  void shouldHandleErrorWhenNoKeyProvided(FxRobot robot) {
    TextArea textInput = robot.lookup("#textInput").queryAs(TextArea.class);
    ComboBox<String> signatureSchemeDropdown = robot.lookup("#signatureSchemeDropdown")
        .queryAs(ComboBox.class);
    robot.clickOn(textInput).write("Valid text to sign.");
    robot.clickOn(signatureSchemeDropdown);
    robot.clickOn("PKCS#1 v1.5");
    robot.clickOn("#createSignatureButton");
    assertNotNull((Node) robot.lookup(button -> button instanceof Button &&
            ((Button) button).getText().equals(ButtonType.OK.getText())).tryQuery().orElseThrow(
            () -> new AssertionError("Button with text '" + ButtonType.OK.getText() + "' not found.")
        ),
        "Failure popup box ok button should exist.");
  }

  /**
   * Tests the application's behavior when attempting to create a signature without entering any
   * text.
   *
   * @param robot The robot used to simulate user interactions.
   * @throws NoSuchFieldException   if a field with the specified name is not found.
   * @throws IllegalAccessException if this {@code Field} object is enforcing Java language access
   *                                control and the underlying field is inaccessible.
   * @throws IOException            if an I/O error occurs while handling the key files.
   */
  @Test
  void shouldHandleErrorWhenNoTextEntered(FxRobot robot)
      throws NoSuchFieldException, IllegalAccessException, IOException {
    ComboBox<String> signatureSchemeDropdown = robot.lookup("#signatureSchemeDropdown")
        .queryAs(ComboBox.class);

    // Import key or simulate importing key
    Field signView = SignatureController.class.getDeclaredField("signView");
    signView.setAccessible(true);
    SignView signViewVal = (SignView) signView.get(mainController.getSignatureController());
    GenRSA genRSA = new GenRSA(2, new int[]{512, 512});
    KeyPair keyPair = genRSA.generateKeyPair();

    keyPair.getPrivateKey().exportKey("key.rsa");
    keyPair.getPublicKey().exportKey("publicKey.rsa");
    Optional<File> privateKeyFile = uk.msci.project.tests.MainTestUtility.
        getFile("key", ".rsa");
    // Simulate invoking the file import method directly
    Platform.runLater(() -> {
      mainController.getSignatureController()
          .handleMessageFile(privateKeyFile.get(), signViewVal);
    });

    // Give some time for the UI to update and for the file to be processed
    WaitForAsyncUtils.waitForFxEvents();

    // Select a valid signature scheme
    robot.clickOn(signatureSchemeDropdown);
    robot.clickOn("PKCS#1 v1.5");

    // Attempt to create a signature with no text entered
    robot.clickOn("#createSignatureButton");
    assertNotNull((Node) robot.lookup(button -> button instanceof Button &&
            ((Button) button).getText().equals(ButtonType.OK.getText())).tryQuery().orElseThrow(
            () -> new AssertionError("Button with text '" + ButtonType.OK.getText() + "' not found.")
        ),
        "Failure popup box ok button should exist.");
  }

  /**
   * Verifies that the application displays an error when trying to create a signature without
   * selecting a signature scheme.
   *
   * @param robot The robot used to simulate user interactions.
   * @throws NoSuchFieldException   if the signature view field is not found in the
   *                                SignatureController.
   * @throws IllegalAccessException if the signature view field is inaccessible.
   * @throws IOException            if there is an issue handling the key files.
   */
  @Test
  void shouldHandleErrorWhenNoSchemeSelected(FxRobot robot)
      throws NoSuchFieldException, IllegalAccessException, IOException {
    TextArea textInput = robot.lookup("#textInput").queryAs(TextArea.class);
    robot.clickOn(textInput).write("Valid text to sign.");
    ComboBox<String> signatureSchemeDropdown = robot.lookup("#signatureSchemeDropdown")
        .queryAs(ComboBox.class);

    // Import key or simulate importing key
    Field signView = SignatureController.class.getDeclaredField("signView");
    signView.setAccessible(true);
    SignView signViewVal = (SignView) signView.get(mainController.getSignatureController());
    GenRSA genRSA = new GenRSA(2, new int[]{512, 512});
    KeyPair keyPair = genRSA.generateKeyPair();

    keyPair.getPrivateKey().exportKey("key.rsa");
    keyPair.getPublicKey().exportKey("publicKey.rsa");
    Optional<File> privateKeyFile = uk.msci.project.tests.MainTestUtility.
        getFile("key", ".rsa");
    // Simulate invoking the file import method directly
    Platform.runLater(() -> {
      mainController.getSignatureController()
          .handleKey(privateKeyFile.get(), signViewVal);
    });

    WaitForAsyncUtils.waitForFxEvents();

    // Attempt to create a signature with no scheme selected
    robot.clickOn("#createSignatureButton");
    assertNotNull((Node) robot.lookup(button -> button instanceof Button &&
            ((Button) button).getText().equals(ButtonType.OK.getText())).tryQuery().orElseThrow(
            () -> new AssertionError("Button with text '" + ButtonType.OK.getText() + "' not found.")
        ),
        "Failure popup box ok button should exist.");
  }

  /**
   * Tests the application's behavior when a corrupted key file is used for signing.
   *
   * @param robot The robot used to simulate user interactions.
   * @throws NoSuchFieldException   if the signature view field is not found in the
   *                                SignatureController.
   * @throws IllegalAccessException if the signature view field is inaccessible.
   * @throws IOException            if there is an issue handling the key files.
   */
  @Test
  void shouldHandleErrorWhenCorruptedKey(FxRobot robot)
      throws NoSuchFieldException, IllegalAccessException, IOException {
    TextArea textInput = robot.lookup("#textInput").queryAs(TextArea.class);
    robot.clickOn(textInput).write("Valid text to sign.");
    ComboBox<String> signatureSchemeDropdown = robot.lookup("#signatureSchemeDropdown")
        .queryAs(ComboBox.class);

    // Import key or simulate importing key
    Field signView = SignatureController.class.getDeclaredField("signView");
    signView.setAccessible(true);
    SignView signViewVal = (SignView) signView.get(mainController.getSignatureController());
    GenRSA genRSA = new GenRSA(2, new int[]{512, 512});
    KeyPair keyPair = genRSA.generateKeyPair();

    FileHandle.exportToFile("corruptKey.rsa", "awsedfrgttgdfrs");
    Optional<File> corruptKey = uk.msci.project.tests.MainTestUtility.
        getFile("corruptKey", ".rsa");
    // Simulate invoking the file import method directly
    Platform.runLater(() -> {
      mainController.getSignatureController()
          .handleKey(corruptKey.get(), signViewVal);
    });

    WaitForAsyncUtils.waitForFxEvents();
    assertNotNull((Node) robot.lookup(button -> button instanceof Button &&
            ((Button) button).getText().equals(ButtonType.OK.getText())).tryQuery().orElseThrow(
            () -> new AssertionError("Button with text '" + ButtonType.OK.getText() + "' not found.")
        ),
        "Failure popup box ok button should exist.");

  }

  /**
   * Validates the application's ability to successfully create a signature given valid text and a
   * valid key.
   *
   * @param robot The robot used to simulate user interactions.
   * @throws NoSuchFieldException   if the signature view field is not found in the
   *                                SignatureController.
   * @throws IllegalAccessException if the signature view field is inaccessible.
   * @throws IOException            if there is an issue handling the key files.
   */
  @Test
  void shouldCreateSignature(FxRobot robot)
      throws NoSuchFieldException, IllegalAccessException, IOException {
    TextArea textInput = robot.lookup("#textInput").queryAs(TextArea.class);
    robot.clickOn(textInput).write("Valid text to sign.");
    ComboBox<String> signatureSchemeDropdown = robot.lookup("#signatureSchemeDropdown")
        .queryAs(ComboBox.class);

    // Import key or simulate importing key
    Field signView = SignatureController.class.getDeclaredField("signView");
    signView.setAccessible(true);
    SignView signViewVal = (SignView) signView.get(mainController.getSignatureController());
    GenRSA genRSA = new GenRSA(2, new int[]{512, 512});
    KeyPair keyPair = genRSA.generateKeyPair();

    keyPair.getPrivateKey().exportKey("key.rsa");
    keyPair.getPublicKey().exportKey("publicKey.rsa");
    Optional<File> privateKeyFile = uk.msci.project.tests.MainTestUtility.
        getFile("key", ".rsa");
    // Simulate invoking the file import method directly
    Platform.runLater(() -> {
      mainController.getSignatureController()
          .handleKey(privateKeyFile.get(), signViewVal);
    });

    WaitForAsyncUtils.waitForFxEvents();
    // Select a valid signature scheme
    robot.clickOn(signatureSchemeDropdown);
    robot.clickOn("PKCS#1 v1.5");

    // Attempt to create a signature with no scheme selected
    robot.clickOn("#createSignatureButton");
    StackPane successPopUp = robot.lookup("#notificationPane").queryAs(StackPane.class);
    assertTrue(successPopUp.isVisible(),
        "Notification popup indicating creation of signature should be visible");
    //test that export signature works as expected
    testFileExport(robot, "#exportSignatureButton", "signature", ".rsa");

  }

  /**
   * Tests the recovery options provided by the application for long messages using the ISO/IEC
   * 9796-2 Scheme 1 signature scheme.
   *
   * @param robot The robot used to simulate user interactions.
   * @throws NoSuchFieldException   if the signature view field is not found in the
   *                                SignatureController.
   * @throws IllegalAccessException if the signature view field is inaccessible.
   * @throws IOException            if there is an issue handling the key files.
   */
  @Test
  void testISOrecoveryOptionsLongMessage(FxRobot robot)
      throws NoSuchFieldException, IllegalAccessException, IOException {
    TextArea textInput = robot.lookup("#textInput").queryAs(TextArea.class);
    robot.clickOn(textInput).write(
        "Valid text to sign.alid text to sign.alid text to sign.alid te"
            + "xt to sign.alid text to sign.alid text to sign.alid text to sign.alid text to s"
            + "ign.alid text to sign.alid text to sign.alid text to sign.alid text to sign.alid tex"
            + "t to sign.alid text to sign.alid text to sign.alid text to sign.alid text to sign.alid "
            + "text to sign.alid text to sign.alid text to");
    ComboBox<String> signatureSchemeDropdown = robot.lookup("#signatureSchemeDropdown")
        .queryAs(ComboBox.class);

    // Import key or simulate importing key
    Field signView = SignatureController.class.getDeclaredField("signView");
    signView.setAccessible(true);
    SignView signViewVal = (SignView) signView.get(mainController.getSignatureController());
    GenRSA genRSA = new GenRSA(2, new int[]{512, 512});
    KeyPair keyPair = genRSA.generateKeyPair();

    keyPair.getPrivateKey().exportKey("key.rsa");
    keyPair.getPublicKey().exportKey("publicKey.rsa");
    Optional<File> privateKeyFile = uk.msci.project.tests.MainTestUtility.
        getFile("key", ".rsa");
    // Simulate invoking the file import method directly
    Platform.runLater(() -> {
      mainController.getSignatureController()
          .handleKey(privateKeyFile.get(), signViewVal);
    });

    WaitForAsyncUtils.waitForFxEvents();
    // Select a valid signature scheme
    robot.clickOn(signatureSchemeDropdown);
    robot.clickOn("ISO\\IEC 9796-2 Scheme 1");

    // Attempt to create a signature with no scheme selected
    robot.clickOn("#createSignatureButton");
    StackPane successPopUp = robot.lookup("#notificationPane").queryAs(StackPane.class);
    assertTrue(successPopUp.isVisible(),
        "Notification popup indicating creation of signature should be visible");
    HBox recoveryOptions = robot.lookup("#notificationPane").queryAs(HBox.class);
    assertTrue(recoveryOptions.isVisible(),
        "Options to copy or export a non recoverable message should be availa"
            + "ble if a sufficiently long message inputted and the signature scheme is the ISO one");
    //test that export signature works as expected
    testFileExport(robot, "#exportNonRecoverableMessageButton", "nonRecoverableMessage", ".txt");

  }

  /**
   * Verifies that the application does not provide recovery options for short messages when using
   * the ISO/IEC 9796-2 Scheme 1 signature scheme.
   *
   * @param robot The robot used to simulate user interactions.
   * @throws NoSuchFieldException   if the signature view field is not found in the
   *                                SignatureController.
   * @throws IllegalAccessException if the signature view field is inaccessible.
   * @throws IOException            if there is an issue handling the key files.
   */
  @Test
  void testISOrecoveryOptionsShortMessage(FxRobot robot)
      throws NoSuchFieldException, IllegalAccessException, IOException {
    TextArea textInput = robot.lookup("#textInput").queryAs(TextArea.class);
    robot.clickOn(textInput).write(
        "short message");
    ComboBox<String> signatureSchemeDropdown = robot.lookup("#signatureSchemeDropdown")
        .queryAs(ComboBox.class);

    // Import key or simulate importing key
    Field signView = SignatureController.class.getDeclaredField("signView");
    signView.setAccessible(true);
    SignView signViewVal = (SignView) signView.get(mainController.getSignatureController());
    GenRSA genRSA = new GenRSA(2, new int[]{512, 512});
    KeyPair keyPair = genRSA.generateKeyPair();

    keyPair.getPrivateKey().exportKey("key.rsa");
    keyPair.getPublicKey().exportKey("publicKey.rsa");
    Optional<File> privateKeyFile = uk.msci.project.tests.MainTestUtility.
        getFile("key", ".rsa");
    // Simulate invoking the file import method directly
    Platform.runLater(() -> {
      mainController.getSignatureController()
          .handleKey(privateKeyFile.get(), signViewVal);
    });

    WaitForAsyncUtils.waitForFxEvents();
    // Select a valid signature scheme
    robot.clickOn(signatureSchemeDropdown);
    robot.clickOn("ISO\\IEC 9796-2 Scheme 1");

    // Attempt to create a signature with no scheme selected
    robot.clickOn("#createSignatureButton");
    StackPane successPopUp = robot.lookup("#notificationPane").queryAs(StackPane.class);
    assertTrue(successPopUp.isVisible(),
        "Notification popup indicating creation of signature should be visible");
    assertThrows(EmptyNodeQueryException.class,
        () -> robot.lookup("#notificationPane").queryAs(HBox.class),
        "Options to copy or export a non recoverable message should not be availa"
            + "ble if a short message is inputted");


  }


  /**
   * Tests the functionality of navigating back to the main menu from the sign view.
   *
   * @param robot The robot used to simulate user interactions.
   */
  @Test
  void shouldNavigateToMainMenu(FxRobot robot) {
    robot.clickOn("#backToMainMenuButton");
    WaitForAsyncUtils.waitForFxEvents();
    Button node = (Button) robot.lookup("#signDocumentButton").query();
    assertNotNull(node, "The component should exist.");
    // Verify that the button with the text "[K] Generate Keys" is present
    verifyThat("#signDocumentButton", LabeledMatchers.hasText("[S] Sign Document"));
  }

}
