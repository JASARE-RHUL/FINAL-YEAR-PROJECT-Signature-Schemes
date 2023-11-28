package uk.msci.project.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.testfx.api.FxAssert.verifyThat;
import static uk.msci.project.tests.PublicKeyTest.deleteFilesWithSuffix;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.util.Optional;
import java.util.zip.DataFormatException;
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
import org.testfx.util.WaitForAsyncUtils;
import uk.msci.project.rsa.FileHandle;
import uk.msci.project.rsa.GenRSA;
import uk.msci.project.rsa.KeyPair;
import uk.msci.project.rsa.MainController;
import uk.msci.project.rsa.SignatureController;
import uk.msci.project.rsa.SignatureModel;
import uk.msci.project.rsa.SignatureType;
import uk.msci.project.rsa.VerifyView;
import uk.msci.project.rsa.exceptions.InvalidSignatureTypeException;


/**
 * This class provides automated UI tests for the verification feature in the Signature Scheme POC
 * application. It employs the TestFX framework to simulate user interactions with the verification
 * view and ensures that all aspects of the UI are functioning as expected.
 *
 * <p>Each test method is designed to be independent, setting up the necessary preconditions and
 * cleaning up afterwards to avoid side effects that could affect other tests.
 *
 * @see org.junit.jupiter.api.Test
 * @see org.testfx.framework.junit5.ApplicationExtension
 * @see org.testfx.api.FxRobot
 */
@ExtendWith(ApplicationExtension.class)
public class VerifyFunctionalityTest {

  private MainController mainController;

  /**
   * Sets up the main stage for the application before each test is run. This method initializes the
   * main controller of the application, which is responsible for orchestrating the behavior of the
   * UI.
   *
   * @param stage The primary stage for this application provided by the test framework.
   * @throws Exception if the initialization of the stage fails.
   */
  @Start
  public void start(Stage stage) throws Exception {
    mainController = new MainController(stage);
  }

  /**
   * Prepares the application's UI for the verification view before each test. It deletes files with
   * a specific suffix to ensure a clean state and navigates to the verification view by simulating
   * a button click.
   *
   * @param robot The robot used to simulate user interactions for testing.
   */
  @BeforeEach
  public void setup(FxRobot robot) {
    String fileNamePrefix = "testFile";
    String fileExtension = "txt";
    deleteFilesWithSuffix(fileNamePrefix, fileExtension);
    robot.clickOn("#verifySignatureButton");
    WaitForAsyncUtils.waitForFxEvents();

  }

  /**
   * Verifies the presence of all necessary UI components within the verify view.
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
    assertNotNull(robot.lookup("#signatureText").queryAs(TextArea.class));
    assertNotNull(robot.lookup("#verifyBtn").queryAs(Button.class));

  }

  /**
   * Tests the functionality of the import text (for which a signature is to be computed from)
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
    Optional<File> testFile = uk.msci.project.tests.MainTestUtility.
        getFile("testFile", ".txt");
    // Simulate invoking the file import method directly
    Field verifyView = SignatureController.class.getDeclaredField("verifyView");
    verifyView.setAccessible(true);
    VerifyView verifyViewVal = (VerifyView) verifyView.get(mainController.getSignatureController());
    Platform.runLater(() -> {
      mainController.getSignatureController()
          .handleMessageFile(testFile.get(), verifyViewVal);
    });
    WaitForAsyncUtils.waitForFxEvents();

    ImageView importSuccessImage = robot.lookup("#textFileCheckmarkImage").queryAs(ImageView.class);
    assertTrue(importSuccessImage.isVisible(),
        "Green checkmark image should appear indicating a success in importing file");
    verifyThat("#textFileNameLabel", LabeledMatchers.hasText(testFile.get().getName()));

  }

  /**
   * Simulates the action of importing a public key and verifies the UI reflects this action
   * correctly. The test checks if the application displays a green checkmark to indicate the
   * successful import of the public key file and that the key field is updated with the file's
   * name.
   *
   * @param robot The robot used to simulate user interactions for testing.
   */
  @Test
  public void shouldHandleImportPublicKeyAction(FxRobot robot)
      throws IOException, NoSuchFieldException, IllegalAccessException {
    // Test importing public key functionality.
    // Simulate invoking the file import method directly
    Field verifyView = SignatureController.class.getDeclaredField("verifyView");
    verifyView.setAccessible(true);
    VerifyView verifyViewVal = (VerifyView) verifyView.get(mainController.getSignatureController());
    GenRSA genRSA = new GenRSA(2, new int[]{512, 512});
    KeyPair keyPair = genRSA.generateKeyPair();

    keyPair.getPrivateKey().exportKey("key.rsa");
    keyPair.getPublicKey().exportKey("publicKey.rsa");
    Optional<File> publicKeyFile = uk.msci.project.tests.MainTestUtility.
        getFile("publicKey", ".rsa");
    Platform.runLater(() -> {
      mainController.getSignatureController()
          .handleKey(publicKeyFile.get(), verifyViewVal);
    });
    WaitForAsyncUtils.waitForFxEvents();
    ImageView importSuccessImage = robot.lookup("#checkmarkImage").queryAs(ImageView.class);
    assertTrue(importSuccessImage.isVisible(),
        "Green checkmark image should appear indicating a success in importing public key");
    verifyThat("#keyField", TextInputControlMatchers.hasText(publicKeyFile.get().getName()));
  }

  /**
   * Tests the functionality for importing a signature file. It simulates a user selecting and
   * importing a signature and verifies that the application updates the UI to reflect the import
   * success by showing a checkmark and the signature file name.
   *
   * @param robot The robot used to simulate user interactions for testing.
   */
  @Test
  public void shouldHandleImportSignatureAction(FxRobot robot)
      throws IOException, NoSuchFieldException, IllegalAccessException, InvalidSignatureTypeException, DataFormatException {
    // Test importing signature functionality.
    // Simulate file chooser action...
    // Simulate invoking the file import method directly
    Field verifyView = SignatureController.class.getDeclaredField("verifyView");
    verifyView.setAccessible(true);
    VerifyView verifyViewVal = (VerifyView) verifyView.get(mainController.getSignatureController());

    FileHandle.exportToFile("signature.rsa", "mock signature");
    Optional<File> signatureFile = uk.msci.project.tests.MainTestUtility.
        getFile("signature", ".rsa");
    Platform.runLater(() -> {
      mainController.getSignatureController()
          .handleSig(signatureFile.get(), verifyViewVal);
    });
    WaitForAsyncUtils.waitForFxEvents();
    HBox importSuccessBox = robot.lookup("#sigFileHBox").queryAs(HBox.class);
    assertTrue(importSuccessBox.isVisible(),
        "HBox containing Green checkmark image should appear indicating a success in importing signature");
    verifyThat("#sigFileNameLabel", LabeledMatchers.hasText("Signature imported"));

  }

  /**
   * Validates the signature verification process using the UI. It simulates the process of
   * importing text, a public key, and a signature, then initiates the verification process and
   * asserts that the application displays a notification with the result of the verification.
   *
   * @param robot The robot used to simulate user interactions for testing.
   */
  @Test
  public void shouldVerifySignature(FxRobot robot)
      throws NoSuchFieldException, IOException, IllegalAccessException {
    // Test the verification process.
    // Import text, public key, and signature...
    TextArea textInput = robot.lookup("#textInput").queryAs(TextArea.class);
    robot.clickOn(textInput).write("text to sign.");
    Field verifyView = SignatureController.class.getDeclaredField("verifyView");
    verifyView.setAccessible(true);
    VerifyView verifyViewVal = (VerifyView) verifyView.get(mainController.getSignatureController());
    GenRSA genRSA = new GenRSA(2, new int[]{512, 512});
    KeyPair keyPair = genRSA.generateKeyPair();

    keyPair.getPrivateKey().exportKey("key.rsa");
    Optional<File> publicKeyFile = uk.msci.project.tests.MainTestUtility.
        getFile("publicKey", ".rsa");
    Platform.runLater(() -> {
      mainController.getSignatureController()
          .handleKey(publicKeyFile.get(), verifyViewVal);
    });
    WaitForAsyncUtils.waitForFxEvents();
    FileHandle.exportToFile("signature.rsa", "mock signature");
    Optional<File> signatureFile = uk.msci.project.tests.MainTestUtility.
        getFile("signature", ".rsa");
    Platform.runLater(() -> {
      mainController.getSignatureController()
          .handleSig(signatureFile.get(), verifyViewVal);
    });

    // Select a valid signature scheme
    ComboBox<String> signatureSchemeDropdown = robot.lookup("#signatureSchemeDropdown")
        .queryAs(ComboBox.class);
    robot.clickOn(signatureSchemeDropdown);
    WaitForAsyncUtils.waitForFxEvents();
    robot.clickOn("PKCS#1 v1.5");
    WaitForAsyncUtils.waitForFxEvents();
    robot.clickOn("#verifyBtn");
    StackPane verificationCompleteNotification = robot.lookup("#notificationPane")
        .queryAs(StackPane.class);
    assertTrue(verificationCompleteNotification.isVisible(),
        "Notification popup indicating whether signature is valid is displayed");
  }

  /**
   * Ensures that changing the selected signature scheme in the UI updates the application state
   * accordingly. This test interacts with the signature scheme dropdown and asserts that the
   * selected signature type matches the expected value after a selection is made.
   *
   * @param robot The robot used to simulate user interactions for testing.
   */
  @Test
  public void shouldChangeSignatureType(FxRobot robot)
      throws NoSuchFieldException, IllegalAccessException {
    // Test that the signature scheme dropdown changes the signature when a new option is selected.

    Field sigModel = SignatureController.class.getDeclaredField("signatureModel");
    sigModel.setAccessible(true);
    SignatureModel sigModelVal = (SignatureModel) sigModel.get(
        mainController.getSignatureController());
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
   * Tests the application's response to an attempt to verify a signature without entering any text.
   * It expects the application to show an error dialog or notification indicating that the text is
   * missing.
   *
   * @param robot The robot used to simulate user interactions for testing.
   */
  @Test
  public void shouldHandleErrorWhenNoTextEntered(FxRobot robot)
      throws NoSuchFieldException, IOException, IllegalAccessException {
    Field verifyView = SignatureController.class.getDeclaredField("verifyView");
    verifyView.setAccessible(true);
    VerifyView verifyViewVal = (VerifyView) verifyView.get(mainController.getSignatureController());
    GenRSA genRSA = new GenRSA(2, new int[]{512, 512});
    KeyPair keyPair = genRSA.generateKeyPair();

    keyPair.getPrivateKey().exportKey("key.rsa");
    Optional<File> publicKeyFile = uk.msci.project.tests.MainTestUtility.
        getFile("publicKey", ".rsa");
    Platform.runLater(() -> {
      mainController.getSignatureController()
          .handleKey(publicKeyFile.get(), verifyViewVal);
    });
    WaitForAsyncUtils.waitForFxEvents();
    FileHandle.exportToFile("signature.rsa", "mock signature");
    Optional<File> signatureFile = uk.msci.project.tests.MainTestUtility.
        getFile("signature", ".rsa");
    Platform.runLater(() -> {
      mainController.getSignatureController()
          .handleSig(signatureFile.get(), verifyViewVal);
    });

    // Select a valid signature scheme
    ComboBox<String> signatureSchemeDropdown = robot.lookup("#signatureSchemeDropdown")
        .queryAs(ComboBox.class);
    robot.clickOn(signatureSchemeDropdown);
    WaitForAsyncUtils.waitForFxEvents();
    robot.clickOn("PKCS#1 v1.5");
    WaitForAsyncUtils.waitForFxEvents();
    robot.clickOn("#verifyBtn");
    assertNotNull((Node) robot.lookup(button -> button instanceof Button &&
            ((Button) button).getText().equals(ButtonType.OK.getText())).tryQuery().orElseThrow(
            () -> new AssertionError("Button with text '" + ButtonType.OK.getText() + "' not found.")
        ),
        "Failure popup box ok button should exist.");
  }

  /**
   * Verifies that the application correctly handles the scenario where no public key is provided
   * during the signature verification process. It should prompt the user with an error.
   *
   * @param robot The robot used to simulate user interactions for testing.
   */
  @Test
  public void shouldHandleErrorWhenNoKeyProvided(FxRobot robot)
      throws NoSuchFieldException, IOException, IllegalAccessException {
    // Test the verification process.
    // Import text, public key, and signature...
    TextArea textInput = robot.lookup("#textInput").queryAs(TextArea.class);
    robot.clickOn(textInput).write("text to sign.");
    Field verifyView = SignatureController.class.getDeclaredField("verifyView");
    verifyView.setAccessible(true);
    VerifyView verifyViewVal = (VerifyView) verifyView.get(mainController.getSignatureController());

    FileHandle.exportToFile("signature.rsa", "mock signature");
    Optional<File> signatureFile = uk.msci.project.tests.MainTestUtility.
        getFile("signature", ".rsa");
    Platform.runLater(() -> {
      mainController.getSignatureController()
          .handleSig(signatureFile.get(), verifyViewVal);
    });

    // Select a valid signature scheme
    ComboBox<String> signatureSchemeDropdown = robot.lookup("#signatureSchemeDropdown")
        .queryAs(ComboBox.class);
    robot.clickOn(signatureSchemeDropdown);
    WaitForAsyncUtils.waitForFxEvents();
    robot.clickOn("PKCS#1 v1.5");
    WaitForAsyncUtils.waitForFxEvents();
    robot.clickOn("#verifyBtn");
    assertNotNull((Node) robot.lookup(button -> button instanceof Button &&
            ((Button) button).getText().equals(ButtonType.OK.getText())).tryQuery().orElseThrow(
            () -> new AssertionError("Button with text '" + ButtonType.OK.getText() + "' not found.")
        ),
        "Failure popup box ok button should exist.");
  }

  /**
   * Tests the application's response when no signature is provided for verification. An error
   * message or dialog should be presented to the user.
   *
   * @param robot The robot used to simulate user interactions for testing.
   */
  @Test
  public void shouldHandleErrorWhenNoSignatureProvided(FxRobot robot)
      throws NoSuchFieldException, IOException, IllegalAccessException {
    // Test the verification process.

    TextArea textInput = robot.lookup("#textInput").queryAs(TextArea.class);
    robot.clickOn(textInput).write("text to sign.");
    Field verifyView = SignatureController.class.getDeclaredField("verifyView");
    verifyView.setAccessible(true);
    VerifyView verifyViewVal = (VerifyView) verifyView.get(mainController.getSignatureController());
    GenRSA genRSA = new GenRSA(2, new int[]{512, 512});
    KeyPair keyPair = genRSA.generateKeyPair();

    keyPair.getPrivateKey().exportKey("key.rsa");
    Optional<File> publicKeyFile = uk.msci.project.tests.MainTestUtility.
        getFile("publicKey", ".rsa");
    Platform.runLater(() -> {
      mainController.getSignatureController()
          .handleKey(publicKeyFile.get(), verifyViewVal);
    });
    WaitForAsyncUtils.waitForFxEvents();

    // Select a valid signature scheme
    ComboBox<String> signatureSchemeDropdown = robot.lookup("#signatureSchemeDropdown")
        .queryAs(ComboBox.class);
    robot.clickOn(signatureSchemeDropdown);
    WaitForAsyncUtils.waitForFxEvents();
    robot.clickOn("PKCS#1 v1.5");
    WaitForAsyncUtils.waitForFxEvents();
    robot.clickOn("#verifyBtn");
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
  public void shouldHandleErrorWhenNoSchemeSelected(FxRobot robot)
      throws NoSuchFieldException, IOException, IllegalAccessException {
    // Test the verification process.
    // Import text, public key, and signature...
    TextArea textInput = robot.lookup("#textInput").queryAs(TextArea.class);
    robot.clickOn(textInput).write("text to sign.");
    Field verifyView = SignatureController.class.getDeclaredField("verifyView");
    verifyView.setAccessible(true);
    VerifyView verifyViewVal = (VerifyView) verifyView.get(mainController.getSignatureController());
    GenRSA genRSA = new GenRSA(2, new int[]{512, 512});
    KeyPair keyPair = genRSA.generateKeyPair();

    keyPair.getPrivateKey().exportKey("key.rsa");
    Optional<File> publicKeyFile = uk.msci.project.tests.MainTestUtility.
        getFile("publicKey", ".rsa");
    Platform.runLater(() -> {
      mainController.getSignatureController()
          .handleKey(publicKeyFile.get(), verifyViewVal);
    });
    WaitForAsyncUtils.waitForFxEvents();
    FileHandle.exportToFile("signature.rsa", "mock signature");
    Optional<File> signatureFile = uk.msci.project.tests.MainTestUtility.
        getFile("signature", ".rsa");
    Platform.runLater(() -> {
      mainController.getSignatureController()
          .handleSig(signatureFile.get(), verifyViewVal);
    });

    robot.clickOn("#verifyBtn");
    assertNotNull((Node) robot.lookup(button -> button instanceof Button &&
            ((Button) button).getText().equals(ButtonType.OK.getText())).tryQuery().orElseThrow(
            () -> new AssertionError("Button with text '" + ButtonType.OK.getText() + "' not found.")
        ),
        "Failure popup box ok button should exist.");
  }

  /**
   * Confirms that the application shows an appropriate error when all fields (text, key, signature)
   * are left empty and an attempt is made to verify the signature.
   *
   * @param robot The robot used to simulate user interactions for testing.
   */
  @Test
  public void shouldHandleAllFieldsEmpty(FxRobot robot)
      throws NoSuchFieldException, IOException, IllegalAccessException {

    robot.clickOn("#verifyBtn");
    assertNotNull((Node) robot.lookup(button -> button instanceof Button &&
            ((Button) button).getText().equals(ButtonType.OK.getText())).tryQuery().orElseThrow(
            () -> new AssertionError("Button with text '" + ButtonType.OK.getText() + "' not found.")
        ),
        "Failure popup box ok button should exist.");
  }

  /**
   * Ensures that the application properly notifies the user when the provided public key is
   * corrupted or otherwise unreadable. This is crucial for maintaining integrity during the
   * verification process.
   *
   * @param robot The robot used to simulate user interactions for testing.
   */
  @Test
  public void shouldHandleErrorWhenCorruptedKey(FxRobot robot)
      throws NoSuchFieldException, IOException, IllegalAccessException {
    Field verifyView = SignatureController.class.getDeclaredField("verifyView");
    verifyView.setAccessible(true);
    VerifyView verifyViewVal = (VerifyView) verifyView.get(mainController.getSignatureController());
    GenRSA genRSA = new GenRSA(2, new int[]{512, 512});
    KeyPair keyPair = genRSA.generateKeyPair();

    keyPair.getPrivateKey().exportKey("key.rsa");
    FileHandle.exportToFile("corruptKey.rsa", "awsedfrgttgdfrs");
    Optional<File> corruptKey = uk.msci.project.tests.MainTestUtility.
        getFile("corruptKey", ".rsa");
    // Simulate invoking the file import method directly
    Platform.runLater(() -> {
      mainController.getSignatureController()
          .handleKey(corruptKey.get(), verifyViewVal);
    });
    WaitForAsyncUtils.waitForFxEvents();

    assertNotNull((Node) robot.lookup(button -> button instanceof Button &&
            ((Button) button).getText().equals(ButtonType.OK.getText())).tryQuery().orElseThrow(
            () -> new AssertionError("Button with text '" + ButtonType.OK.getText() + "' not found.")
        ),
        "Failure popup box ok button should exist.");
  }

  /**
   * Tests the application's response to an attempt to verify an signature ISO message recovery
   * signature without entering any text. It expects the application to show proceed with
   * verification since the ISO scheme in full message recovery mode does not require a message
   * input and instead recovers the full initial message submitted to the signature creation
   * process
   *
   * @param robot The robot used to simulate user interactions for testing.
   */
  @Test
  public void shouldAllowEmptyMessageWhenISOSelected(FxRobot robot)
      throws NoSuchFieldException, IOException, IllegalAccessException {
    Field verifyView = SignatureController.class.getDeclaredField("verifyView");
    verifyView.setAccessible(true);
    VerifyView verifyViewVal = (VerifyView) verifyView.get(mainController.getSignatureController());
    GenRSA genRSA = new GenRSA(2, new int[]{512, 512});
    KeyPair keyPair = genRSA.generateKeyPair();

    keyPair.getPrivateKey().exportKey("key.rsa");
    Optional<File> publicKeyFile = uk.msci.project.tests.MainTestUtility.
        getFile("publicKey", ".rsa");
    Platform.runLater(() -> {
      mainController.getSignatureController()
          .handleKey(publicKeyFile.get(), verifyViewVal);
    });
    WaitForAsyncUtils.waitForFxEvents();
    FileHandle.exportToFile("signature.rsa", "mock signature");
    Optional<File> signatureFile = uk.msci.project.tests.MainTestUtility.
        getFile("signature", ".rsa");
    Platform.runLater(() -> {
      mainController.getSignatureController()
          .handleSig(signatureFile.get(), verifyViewVal);
    });

    // Select a valid signature scheme
    ComboBox<String> signatureSchemeDropdown = robot.lookup("#signatureSchemeDropdown")
        .queryAs(ComboBox.class);
    robot.clickOn(signatureSchemeDropdown);
    WaitForAsyncUtils.waitForFxEvents();
    robot.clickOn("ISO\\IEC 9796-2 Scheme 1");
    WaitForAsyncUtils.waitForFxEvents();
    robot.clickOn("#verifyBtn");
    StackPane verificationCompleteNotification = robot.lookup("#notificationPane")
        .queryAs(StackPane.class);
    assertTrue(verificationCompleteNotification.isVisible(),
        "Notification popup indicating whether signature is valid is displayed");
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
    Button node = (Button) robot.lookup("#verifySignatureButton").query();
    assertNotNull(node, "The component should exist.");
    // Verify that the button with the text "[K] Generate Keys" is present
    verifyThat("#verifySignatureButton", LabeledMatchers.hasText("[V] Verify Signature"));
  }

}
