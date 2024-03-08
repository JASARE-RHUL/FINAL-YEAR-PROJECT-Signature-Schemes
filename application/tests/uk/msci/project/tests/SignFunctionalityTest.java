package uk.msci.project.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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
import javafx.scene.image.ImageView;
import javafx.scene.layout.HBox;
import javafx.scene.layout.StackPane;
import javafx.stage.Stage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.testfx.api.FxRobot;
import org.testfx.framework.junit5.ApplicationExtension;
import org.testfx.framework.junit5.Start;
import org.testfx.matcher.control.LabeledMatchers;
import org.testfx.matcher.control.TextInputControlMatchers;
import org.testfx.service.query.EmptyNodeQueryException;
import org.testfx.util.WaitForAsyncUtils;
import uk.msci.project.rsa.FileHandle;
import uk.msci.project.rsa.GenRSA;
import uk.msci.project.rsa.KeyPair;
import uk.msci.project.rsa.MainController;
import uk.msci.project.rsa.SignView;
import uk.msci.project.rsa.SignatureCreationController;
import uk.msci.project.rsa.SignatureModel;
import uk.msci.project.rsa.SignatureType;


/**
 * This class provides automated UI tests for the signature generation feature in the Signature
 * Scheme POC application. It employs the TestFX framework to simulate user interactions with the
 * verification view and ensures that all aspects of the UI are functioning as expected.
 *
 * <p>Each test method is designed to be independent, setting up the necessary preconditions and
 * cleaning up afterwards to avoid side effects that could affect other tests.
 *
 * @see Test
 * @see ApplicationExtension
 * @see FxRobot
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
   * Prepares the application's UI for the sign view before each test. It deletes files with a
   * specific suffix to ensure a clean state and navigates to the sign view by simulating a button
   * click.
   *
   * @param robot The robot used to simulate user interactions for testing.
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
    Field signView = SignatureCreationController.class.getDeclaredField("signView");
    signView.setAccessible(true);
    SignView signViewVal = (SignView) signView.get(mainController.getSignatureCreationControllerStandard());
    GenRSA genRSA = new GenRSA(2, new int[]{512, 512});
    KeyPair keyPair = genRSA.generateKeyPair();

    keyPair.getPrivateKey().exportKey("key.rsa");
    keyPair.getPublicKey().exportKey("publicKey.rsa");
    Optional<File> privateKeyFile = MainTestUtility.
        getFile("key", ".rsa");
    // Simulate invoking the file import method directly
    Platform.runLater(() -> {
      mainController.getSignatureCreationControllerStandard()
          .handleMessageFile(privateKeyFile.get(), signViewVal, null);
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
   *                                SignatureCreationController.
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
    Field signView = SignatureCreationController.class.getDeclaredField("signView");
    signView.setAccessible(true);
    SignView signViewVal = (SignView) signView.get(mainController.getSignatureCreationControllerStandard());
    GenRSA genRSA = new GenRSA(2, new int[]{512, 512});
    KeyPair keyPair = genRSA.generateKeyPair();

    keyPair.getPrivateKey().exportKey("key.rsa");
    keyPair.getPublicKey().exportKey("publicKey.rsa");
    Optional<File> privateKeyFile = MainTestUtility.
        getFile("key", ".rsa");
    // Simulate invoking the file import method directly
    Platform.runLater(() -> {
      mainController.getSignatureCreationControllerStandard()
          .handleKey(privateKeyFile.get(), signViewVal, null);
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
   * Ensures that the application properly notifies the user when the provided public key is
   * corrupted or otherwise unreadable.
   *
   * @param robot The robot used to simulate user interactions.
   * @throws NoSuchFieldException   if the signature view field is not found in the
   *                                SignatureCreationController.
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
    Field signView = SignatureCreationController.class.getDeclaredField("signView");
    signView.setAccessible(true);
    SignView signViewVal = (SignView) signView.get(mainController.getSignatureCreationControllerStandard());
    GenRSA genRSA = new GenRSA(2, new int[]{512, 512});
    KeyPair keyPair = genRSA.generateKeyPair();

    FileHandle.exportToFile("corruptKey.rsa", "awsedfrgttgdfrs");
    Optional<File> corruptKey = MainTestUtility.
        getFile("corruptKey", ".rsa");
    // Simulate invoking the file import method directly
    Platform.runLater(() -> {
      mainController.getSignatureCreationControllerStandard()
          .handleKey(corruptKey.get(), signViewVal, null);
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
   * valid key. It simulates the process of importing a private key.
   *
   * @param robot The robot used to simulate user interactions.
   * @throws NoSuchFieldException   if the signature view field is not found in the
   *                                SignatureCreationController.
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
    Field signView = SignatureCreationController.class.getDeclaredField("signView");
    signView.setAccessible(true);
    SignView signViewVal = (SignView) signView.get(mainController.getSignatureCreationControllerStandard());
    GenRSA genRSA = new GenRSA(2, new int[]{512, 512});
    KeyPair keyPair = genRSA.generateKeyPair();

    keyPair.getPrivateKey().exportKey("key.rsa");
    keyPair.getPublicKey().exportKey("publicKey.rsa");
    Optional<File> privateKeyFile = MainTestUtility.
        getFile("key", ".rsa");
    // Simulate invoking the file import method directly
    Platform.runLater(() -> {
      mainController.getSignatureCreationControllerStandard()
          .handleKey(privateKeyFile.get(), signViewVal, null);
    });

    WaitForAsyncUtils.waitForFxEvents();
    // Select a valid signature scheme
    robot.clickOn(signatureSchemeDropdown);
    robot.clickOn("PKCS#1 v1.5");

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
   *                                SignatureCreationController.
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
    Field signView = SignatureCreationController.class.getDeclaredField("signView");
    signView.setAccessible(true);
    SignView signViewVal = (SignView) signView.get(mainController.getSignatureCreationControllerStandard());
    GenRSA genRSA = new GenRSA(2, new int[]{512, 512});
    KeyPair keyPair = genRSA.generateKeyPair();

    keyPair.getPrivateKey().exportKey("key.rsa");
    keyPair.getPublicKey().exportKey("publicKey.rsa");
    Optional<File> privateKeyFile = MainTestUtility.
        getFile("key", ".rsa");
    // Simulate invoking the file import method directly
    Platform.runLater(() -> {
      mainController.getSignatureCreationControllerStandard()
          .handleKey(privateKeyFile.get(), signViewVal, null);
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
   *                                SignatureCreationController.
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
    Field signView = SignatureCreationController.class.getDeclaredField("signView");
    signView.setAccessible(true);
    SignView signViewVal = (SignView) signView.get(mainController.getSignatureCreationControllerStandard());
    GenRSA genRSA = new GenRSA(2, new int[]{512, 512});
    KeyPair keyPair = genRSA.generateKeyPair();

    keyPair.getPrivateKey().exportKey("key.rsa");
    keyPair.getPublicKey().exportKey("publicKey.rsa");
    Optional<File> privateKeyFile = MainTestUtility.
        getFile("key", ".rsa");
    // Simulate invoking the file import method directly
    Platform.runLater(() -> {
      mainController.getSignatureCreationControllerStandard()
          .handleKey(privateKeyFile.get(), signViewVal, null);
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

  @Test
  public void shouldChangeSignatureType(FxRobot robot)
      throws NoSuchFieldException, IllegalAccessException {
    // Test that the signature scheme dropdown changes the signature when a new option is selected.

    Field sigModel = SignatureCreationController.class.getDeclaredField("signatureModel");
    sigModel.setAccessible(true);
    SignatureModel sigModelVal = (SignatureModel) sigModel.get(
        mainController.getSignatureCreationControllerStandard());
    ComboBox<String> schemeDropdown = robot.lookup("#signatureSchemeDropdown").queryComboBox();
    assertFalse(schemeDropdown.getItems().isEmpty());
    robot.clickOn(schemeDropdown);
    robot.clickOn("PKCS#1 v1.5");
    assertEquals(SignatureType.RSASSA_PKCS1_v1_5, sigModelVal.getSignatureType());
    robot.clickOn(schemeDropdown);
    robot.clickOn("ANSI X9.31 rDSA");
    assertEquals(SignatureType.ANSI_X9_31_RDSA, sigModelVal.getSignatureType());
    robot.clickOn(schemeDropdown);
    robot.clickOn("ISO\\IEC 9796-2 Scheme 1");
    assertEquals(SignatureType.ISO_IEC_9796_2_SCHEME_1, sigModelVal.getSignatureType());
  }

  /**
   * Tests the functionality of the import text (for which a signature is to be verified with)
   * action. It simulates the action of a user importing a text file and verifies that the UI
   * reflects the successful import of the text.
   *
   * @param robot The robot used to simulate user interactions for testing.
   */
  @Test
  public void shouldHandleImportTextAction(FxRobot robot)
      throws IOException, NoSuchFieldException, IllegalAccessException {
    // Test importing text functionality.
    // Simulate file chooser action...
    FileHandle.exportToFile("testFile.txt", "This is a random test message");
    Optional<File> testFile = MainTestUtility.
        getFile("testFile", ".txt");
    // Simulate invoking the file import method directly
    Field signView = SignatureCreationController.class.getDeclaredField("signView");
    signView.setAccessible(true);
    SignView signViewVal = (SignView) signView.get(mainController.getSignatureCreationControllerStandard());
    Platform.runLater(() -> {
      mainController.getSignatureCreationControllerStandard()
          .handleMessageFile(testFile.get(), signViewVal, null);
    });
    WaitForAsyncUtils.waitForFxEvents();

    ImageView importSuccessImage = robot.lookup("#textFileCheckmarkImage").queryAs(ImageView.class);
    assertTrue(importSuccessImage.isVisible(),
        "Green checkmark image should appear indicating a success in importing file");
    verifyThat("#textFileNameLabel", LabeledMatchers.hasText(testFile.get().getName()));

  }

  /**
   * Simulates the action of importing a private key and verifies the UI reflects this action
   * correctly. The test checks if the application displays a green checkmark to indicate the
   * successful import of the public key file and that the key field is updated with the file's
   * name.
   *
   * @param robot The robot used to simulate user interactions for testing.
   */
  @Test
  public void shouldHandleImportPrivateKeyAction(FxRobot robot)
      throws IOException, NoSuchFieldException, IllegalAccessException {
    // Test importing public key functionality.
    // Simulate invoking the file import method directly
    Field signView = SignatureCreationController.class.getDeclaredField("signView");
    signView.setAccessible(true);
    SignView signViewVal = (SignView) signView.get(mainController.getSignatureCreationControllerStandard());
    GenRSA genRSA = new GenRSA(2, new int[]{512, 512});
    KeyPair keyPair = genRSA.generateKeyPair();

    keyPair.getPrivateKey().exportKey("key.rsa");
    keyPair.getPublicKey().exportKey("publicKey.rsa");
    Optional<File> privateKeyFile = MainTestUtility.
        getFile("key", ".rsa");
    Platform.runLater(() -> {
      mainController.getSignatureCreationControllerStandard()
          .handleKey(privateKeyFile.get(), signViewVal, null);
    });
    WaitForAsyncUtils.waitForFxEvents();
    ImageView importSuccessImage = robot.lookup("#checkmarkImage").queryAs(ImageView.class);
    assertTrue(importSuccessImage.isVisible(),
        "Green checkmark image should appear indicating a success in importing public key");
    verifyThat("#keyField", TextInputControlMatchers.hasText(privateKeyFile.get().getName()));
  }

}
