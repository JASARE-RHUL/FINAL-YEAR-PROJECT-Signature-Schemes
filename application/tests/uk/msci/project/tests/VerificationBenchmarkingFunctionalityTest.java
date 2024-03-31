package uk.msci.project.tests;

import com.jfoenix.controls.JFXTabPane;
import javafx.application.Platform;
import javafx.geometry.VerticalDirection;
import javafx.scene.Node;
import javafx.scene.control.*;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;
import javafx.util.Pair;
import org.controlsfx.control.ToggleSwitch;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.testfx.api.FxRobot;
import org.testfx.framework.junit5.ApplicationExtension;
import org.testfx.framework.junit5.ApplicationTest;
import org.testfx.framework.junit5.Start;
import org.testfx.util.WaitForAsyncUtils;
import uk.msci.project.rsa.*;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.testfx.util.NodeQueryUtils.hasText;
import static uk.msci.project.tests.MainTestUtility.waitForExportDialogToShow;
import static uk.msci.project.tests.PublicKeyTest.deleteFilesWithSuffix;
import static uk.msci.project.tests.SignBenchmarkingFunctionalityTest.createValidMessageBatch;


/**
 * This class provides automated UI tests for the signature verification feature in the Signature
 * Scheme benchmarking application. It employs the TestFX framework to simulate user interactions with the
 * verification view and ensures that all aspects of the UI are functioning as expected.
 *
 * <p>Each test method is designed to be independent, setting up the necessary preconditions and
 * cleaning up afterward to avoid side effects that could affect other tests.
 *
 * @see Test
 * @see ApplicationExtension
 * @see FxRobot
 */
public class VerificationBenchmarkingFunctionalityTest extends ApplicationTest {

  private FxRobot robot;

  private MainController mainController;

  private VerifyView verifyViewVal;

  private SignatureModelBenchmarking signatureModelVal;

  /**
   * Initialises the test fixture with the main stage.
   *
   * @param stage The primary stage for this application.
   */
  @Start
  public void start(Stage stage) {
    mainController = new MainController(stage);
  }

  /**
   * Prepares the application's UI for the verification view before each test.
   * It deletes files with a specific suffix to ensure a clean state and navigates to the verification view by simulating a button click.
   *
   * @throws IllegalAccessException if the fields in the controller are not accessible
   * @throws NoSuchFieldException   if the fields in the controller do not exist
   */
  @BeforeEach
  public void setup() throws IllegalAccessException, NoSuchFieldException {

    String fileNamePrefix = "testFile";
    String fileExtension = "txt";
    deleteFilesWithSuffix(fileNamePrefix, fileExtension);
    robot = new FxRobot();
    robot.clickOn("#verifySignatureButton");
    WaitForAsyncUtils.waitForFxEvents();

    Field verifyViewField = SignatureVerificationControllerBenchmarking.class.getDeclaredField("verifyView");
    verifyViewField.setAccessible(true);
    verifyViewVal = (VerifyView) verifyViewField.get(mainController.getSignatureVerificationControllerBenchmarking());

    Field signatureModelField = SignatureVerificationControllerBenchmarking.class.getDeclaredField("signatureModel");
    signatureModelField.setAccessible(true);
    signatureModelVal = (SignatureModelBenchmarking)
      signatureModelField.get(mainController.getSignatureVerificationControllerBenchmarking());

  }


  /**
   * Verifies the presence of all necessary UI components within the verification view.
   */
  @Test
  void shouldContainUIComponents() {
    // Verifying essential text fields
    assertNotNull(robot.lookup("#messageBatchField").queryAs(TextField.class),
      "Message batch field should exist.");
    assertNotNull(robot.lookup("#keyField").queryAs(TextField.class),
      "Public key batch field should exist.");
    assertNotNull(robot.lookup("#signatureField").queryAs(TextField.class),
      "Signature batch field should exist.");

    // Verifying buttons
    assertNotNull(robot.lookup("#importTextBatchBtn").queryAs(Button.class),
      "Import text batch button should exist.");
    assertNotNull(robot.lookup("#importKeyBatchButton").queryAs(Button.class),
      "Import key batch button should exist.");
    assertNotNull(robot.lookup("#verificationBenchmarkButton").queryAs(Button.class),
      "Start Verification Benchmarking button should exist.");

    // Verifying combo boxes
    assertNotNull(robot.lookup("#signatureSchemeDropdown").queryAs(ComboBox.class),
      "Signature scheme dropdown should exist.");
    assertNotNull(robot.lookup("#hashFunctionDropdown").queryAs(ComboBox.class),
      "Hash function dropdown should exist.");

    // Verifying toggle switches
    assertNotNull(robot.lookup("#benchmarkingModeToggle").queryAs(ToggleSwitch.class),
      "Benchmarking mode toggle should exist.");
    assertNotNull(robot.lookup("#crossParameterBenchmarkingModeToggle").queryAs(ToggleSwitch.class),
      "Cross-parameter benchmarking mode toggle should exist.");

    // Verifying other components
    assertNotNull(robot.lookup("#hashOutputSizeField").queryAs(TextArea.class),
      "Hash output size text area should exist.");
    assertNotNull(robot.lookup("#notificationPane").queryAs(StackPane.class),
      "Overlay notification pane should exist.");
  }


  /**
   * Creates a batch of signature data for testing purposes.
   * Each line in the batch represents a different signature (sequential order).
   *
   * @param filename      The name of the file to write the signatures to.
   * @param numSignatures The number of signatures to create in the batch.
   * @return The file created with the signature batch.
   * @throws IOException If an I/O error occurs while writing the file.
   */
  static File createSignatureBatch(String filename, int numSignatures) throws IOException {
    File file = new File(filename);
    try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
      for (int i = 0; i < numSignatures; i++) {
        writer.write("Signature " + i);
        writer.newLine();
      }
    }
    return file;
  }


  /**
   * Tests the application's behavior with valid input scenarios and verifies that the results of verification
   * and benchmarking processes are displayed correctly.
   *
   * @throws IOException      If there is an issue with file handling during the test.
   * @throws TimeoutException If the test takes longer than the maximum allowable time.
   */
  @Test
  void shouldDisplayResultsOnValidInputs() throws IOException, TimeoutException {
    //valid input means number of messages * number of keys = number of signatures
    // Simulate invoking the file import method directly
    Platform.runLater(() -> {
      try {
        mainController.getSignatureVerificationControllerBenchmarking()
          .handleMessageBatch(createValidMessageBatch("validMessageBatch.txt", 5),
            verifyViewVal,
            signatureModelVal);
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    });

    int[] keyLengths = new int[]{1024, 2048};
    int totalKeys = 2;
    List<Pair<int[], Boolean>> keyParams1 = new ArrayList<>();
    keyParams1.add(new Pair<>(new int[]{256, 256, 512}, false));
    keyParams1.add(new Pair<>(new int[]{512, 512, 1024}, true));

    // Import key or simulate importing key
    GenModelBenchmarking genModelBenchmarking = new GenModelBenchmarking();
    BenchmarkingUtility benchmarkingUtility = new BenchmarkingUtility();
    genModelBenchmarking.batchGenerateKeys(1, keyParams1,
      progress -> Platform.runLater(() -> {
        try {
          benchmarkingUtility.updateProgress(progress);
          benchmarkingUtility.updateProgressLabel(String.format("%.0f%%", progress * 100));
        } catch (NullPointerException e) {
        }
      }));
    WaitForAsyncUtils.waitForFxEvents();
    genModelBenchmarking.generateKeyBatch();
    genModelBenchmarking.exportPrivateKeyBatch();
    genModelBenchmarking.exportPublicKeyBatch();

    Optional<File> validKeyBatch = MainTestUtility.
      getFile("batchPublicKey", ".rsa");
    // Simulate invoking the file import method directly

    Platform.runLater(() -> {
      mainController.getSignatureVerificationControllerBenchmarking()
        .handleKeyBatch(validKeyBatch.get(), verifyViewVal, signatureModelVal);
    });

    WaitForAsyncUtils.waitForFxEvents();


    Platform.runLater(() -> {
      try {
        mainController.getSignatureVerificationControllerBenchmarking()
          .handleSignatureBatch(createSignatureBatch("signatureBatch.rsa", 10), verifyViewVal, signatureModelVal);
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    });

    WaitForAsyncUtils.waitForFxEvents();

    robot.scroll(10, VerticalDirection.UP);
    ComboBox<String> signatureSchemeDropdown = robot.lookup("#signatureSchemeDropdown")
      .queryAs(ComboBox.class);
    robot.clickOn(signatureSchemeDropdown);
    robot.clickOn("PKCS#1 v1.5");
    ComboBox<String> hashFunctionDropdown = lookup("#hashFunctionDropdown").queryComboBox();
    robot.clickOn(hashFunctionDropdown);
    robot.clickOn("SHA-256");
    Platform.runLater(() -> {
      robot.clickOn("#verificationBenchmarkButton");
    });

    WaitForAsyncUtils.waitForFxEvents();


    ProgressBar progressBar = robot.lookup("#progressBar").queryAs(ProgressBar.class);
    WaitForAsyncUtils.waitForFxEvents();
    WaitForAsyncUtils.waitFor(1, TimeUnit.SECONDS, () -> progressBar.getProgress() >= 1);


    // Check that the results title label is displayed and correct
    Platform.runLater(() -> {
      Label resultsTitleLabel = robot.lookup("#resultsLabel").queryAs(Label.class);
      assertEquals("Benchmarking Results for Signature Verification (PKCS#1 v1.5 Signature Scheme-SHA-256)",
        resultsTitleLabel.getText());
    });
    WaitForAsyncUtils.waitForFxEvents();
    // Verify that the JFXTabPane exists
    JFXTabPane sideTabContainer = robot.lookup("#sideTabContainer").queryAs(JFXTabPane.class);
    assertNotNull(sideTabContainer, "The side tab container should be present.");

    assertEquals(totalKeys, sideTabContainer.getTabs().size(), "There should be tabs equal to the total number of keys.");
    robot.scroll(10, VerticalDirection.UP);

    for (int i = 0; i < totalKeys; i++) {

      Tab keyTab = sideTabContainer.getTabs().get(i);

      // Check for the presence of the VBox containing the image and label
      VBox graphicBox = (VBox) keyTab.getGraphic();

      assertNotNull(graphicBox, "Each key tab should have a VBox graphic.");
      robot.clickOn(graphicBox);

      // Check the VBox has two children: ImageView and Label
      List<Node> vboxChildren = graphicBox.getChildren();
      assertEquals(2, vboxChildren.size(), "The graphic box should have an image and a label.");

      // Check for Label and its text
      Label keyLabel = (Label) vboxChildren.get(1);
      assertEquals("Key " + (i + 1) + " (" + keyLengths[i] + "bit)", keyLabel.getText(),
        "The label should have the correct text.");


      Button exportBenchmarkingResultsBtn = robot.lookup("#exportBenchmarkingResultsBtn").queryAs(Button.class);
      Button exportVerificationResultsBtn = robot.lookup("#exportVerificationResultsBtn").queryAs(Button.class);


      robot.clickOn(exportBenchmarkingResultsBtn);
      waitForExportDialogToShow(robot);
      robot.clickOn(robot
        .from(((Stage) robot.window("Export")).getScene().getRoot())
        .lookup(".button")
        .match(hasText("OK"))
        .queryButton());
      robot.clickOn(exportVerificationResultsBtn);
      waitForExportDialogToShow(robot);
      robot.clickOn(robot
        .from(((Stage) robot.window("Export")).getScene().getRoot())
        .lookup(".button")
        .match(hasText("OK"))
        .queryButton());
      WaitForAsyncUtils.waitForFxEvents();


      Optional<File> benchmarkingResultsFile = MainTestUtility.getFile(
        "Benchmarking Results for Signature Verification (PKCS#1 v1.5 Signature Scheme)_" +
          keyLengths[i] + "bit", ".csv");
      assertTrue(benchmarkingResultsFile.isPresent(), "Expected export file not found.");
      assertTrue(benchmarkingResultsFile.get().exists(), "Exported file should exist.");
      Optional<File> verificationResultsFile = MainTestUtility.getFile(
        "verificationResults_" + keyLengths[i] + "bit_PKCS#1_v1.5_Signature_Scheme", ".csv");
      assertTrue(verificationResultsFile.isPresent(), "Expected export file not found.");
      assertTrue(verificationResultsFile.get().exists(), "Exported file should exist.");

      // Verify that the statistics table is populated
      TableView<?> tableView = robot.lookup("#tableView").queryAs(TableView.class);
      assertFalse(tableView.getItems().isEmpty(), "The table should have data.");


    }


  }

  /**
   * Tests the application's behavior with valid input scenarios specifically for the ISO message recovery scheme
   * and verifies that the results are displayed correctly.
   *
   * @throws IOException      If there is an issue with file handling during the test.
   * @throws TimeoutException If the test takes longer than the maximum allowable time.
   */
  @Test
  void shouldDisplayResultsOnValidInputForISO() throws IOException, TimeoutException {
    //valid input means equal number of non-recoverable messages and signature
    // Simulate invoking the file import method directly
    Platform.runLater(() -> {
      try {
        mainController.getSignatureVerificationControllerBenchmarking()
          .handleMessageBatch(createValidMessageBatch("validMessageBatch.txt", 10),
            verifyViewVal,
            signatureModelVal);
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    });

    int[] keyLengths = new int[]{1024, 2048};
    int totalKeys = 2;
    List<Pair<int[], Boolean>> keyParams1 = new ArrayList<>();
    keyParams1.add(new Pair<>(new int[]{256, 256, 512}, false));
    keyParams1.add(new Pair<>(new int[]{512, 512, 1024}, true));

    // Import key or simulate importing key
    GenModelBenchmarking genModelBenchmarking = new GenModelBenchmarking();
    BenchmarkingUtility benchmarkingUtility = new BenchmarkingUtility();
    genModelBenchmarking.batchGenerateKeys(1, keyParams1,
      progress -> Platform.runLater(() -> {
        try {
          benchmarkingUtility.updateProgress(progress);
          benchmarkingUtility.updateProgressLabel(String.format("%.0f%%", progress * 100));
        } catch (NullPointerException e) {
        }
      }));
    WaitForAsyncUtils.waitForFxEvents();
    genModelBenchmarking.generateKeyBatch();
    genModelBenchmarking.exportPrivateKeyBatch();
    genModelBenchmarking.exportPublicKeyBatch();

    Optional<File> validKeyBatch = MainTestUtility.
      getFile("batchPublicKey", ".rsa");
    // Simulate invoking the file import method directly

    Platform.runLater(() -> {
      mainController.getSignatureVerificationControllerBenchmarking()
        .handleKeyBatch(validKeyBatch.get(), verifyViewVal, signatureModelVal);
    });

    WaitForAsyncUtils.waitForFxEvents();


    Platform.runLater(() -> {
      try {
        mainController.getSignatureVerificationControllerBenchmarking()
          .handleSignatureBatch(createSignatureBatch("signatureBatch.rsa", 10), verifyViewVal, signatureModelVal);
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    });

    WaitForAsyncUtils.waitForFxEvents();

    robot.scroll(10, VerticalDirection.UP);
    ComboBox<String> signatureSchemeDropdown = robot.lookup("#signatureSchemeDropdown")
      .queryAs(ComboBox.class);
    robot.clickOn(signatureSchemeDropdown);
    robot.clickOn("ISO\\IEC 9796-2 Scheme 1");
    ComboBox<String> hashFunctionDropdown = lookup("#hashFunctionDropdown").queryComboBox();
    robot.clickOn(hashFunctionDropdown);
    robot.clickOn("SHA-256");
    Platform.runLater(() -> {
      robot.clickOn("#verificationBenchmarkButton");
    });

    WaitForAsyncUtils.waitForFxEvents();


    ProgressBar progressBar = robot.lookup("#progressBar").queryAs(ProgressBar.class);
    WaitForAsyncUtils.waitForFxEvents();
    WaitForAsyncUtils.waitFor(1, TimeUnit.SECONDS, () -> progressBar.getProgress() >= 1);


    // Check that the results title label is displayed and correct
    Platform.runLater(() -> {
      Label resultsTitleLabel = robot.lookup("#resultsLabel").queryAs(Label.class);
      assertEquals("Benchmarking Results for Signature Verification (ISO/IEC 9796-2 Scheme 1-SHA-256)",
        resultsTitleLabel.getText());
    });
    WaitForAsyncUtils.waitForFxEvents();
    // Verify that the JFXTabPane exists
    JFXTabPane sideTabContainer = robot.lookup("#sideTabContainer").queryAs(JFXTabPane.class);
    assertNotNull(sideTabContainer, "The side tab container should be present.");

    assertEquals(totalKeys, sideTabContainer.getTabs().size(), "There should be tabs equal to the total number of keys.");
    robot.scroll(10, VerticalDirection.UP);

    for (int i = 0; i < totalKeys; i++) {

      Tab keyTab = sideTabContainer.getTabs().get(i);

      // Check for the presence of the VBox containing the image and label
      VBox graphicBox = (VBox) keyTab.getGraphic();

      assertNotNull(graphicBox, "Each key tab should have a VBox graphic.");
      robot.clickOn(graphicBox);

      // Check the VBox has two children: ImageView and Label
      List<Node> vboxChildren = graphicBox.getChildren();
      assertEquals(2, vboxChildren.size(), "The graphic box should have an image and a label.");

      // Check for Label and its text
      Label keyLabel = (Label) vboxChildren.get(1);
      assertEquals("Key " + (i + 1) + " (" + keyLengths[i] + "bit)", keyLabel.getText(),
        "The label should have the correct text.");


      Button exportBenchmarkingResultsBtn = robot.lookup("#exportBenchmarkingResultsBtn").queryAs(Button.class);
      Button exportVerificationResultsBtn = robot.lookup("#exportVerificationResultsBtn").queryAs(Button.class);


      robot.clickOn(exportBenchmarkingResultsBtn);
      waitForExportDialogToShow(robot);
      robot.clickOn(robot
        .from(((Stage) robot.window("Export")).getScene().getRoot())
        .lookup(".button")
        .match(hasText("OK"))
        .queryButton());
      robot.clickOn(exportVerificationResultsBtn);
      waitForExportDialogToShow(robot);
      robot.clickOn(robot
        .from(((Stage) robot.window("Export")).getScene().getRoot())
        .lookup(".button")
        .match(hasText("OK"))
        .queryButton());
      WaitForAsyncUtils.waitForFxEvents();


      Optional<File> benchmarkingResultsFile = MainTestUtility.getFile(
        "Benchmarking Results for Signature Verification (ISO-IEC 9796-2 Scheme 1)_" +
          keyLengths[i] + "bit", ".csv");
      assertTrue(benchmarkingResultsFile.isPresent(), "Expected export file not found.");
      assertTrue(benchmarkingResultsFile.get().exists(), "Exported file should exist.");
      Optional<File> verificationResultsFile = MainTestUtility.getFile(
        "verificationResults_" + keyLengths[i] + "bit_ISO-IEC_9796-2_Scheme_1", ".csv");
      assertTrue(verificationResultsFile.isPresent(), "Expected export file not found.");
      assertTrue(verificationResultsFile.get().exists(), "Exported file should exist.");

      // Verify that the statistics table is populated
      TableView<?> tableView = robot.lookup("#tableView").queryAs(TableView.class);
      assertFalse(tableView.getItems().isEmpty(), "The table should have data.");


    }


  }


  /**
   * Provides pairs of message and signature counts that are expected to cause failures during the verification benchmarking process
   * due to unbalanced pairs for Appendix schemes.
   *
   * @return Stream of arguments containing the number of messages and the number of signatures.
   */
  private static Stream<Arguments> provideMessageSignaturePairsForFailureAppendix() {
    return Stream.of(
      Arguments.of(5, 5),
      Arguments.of(3, 5)
    );
  }


  /**
   * Parameterised test that checks for the application's ability to handle cases
   * where the number of messages and signatures are unbalanced for Appendix signature schemes.
   * This mismatch is expected to cause a verification failure.
   *
   * @param messageCount   The number of messages to be used in the test.
   * @param signatureCount The number of signatures to be used in the test.
   * @throws IOException If an I/O error occurs during the test.
   */
  @ParameterizedTest
  @MethodSource("provideMessageSignaturePairsForFailureAppendix")
  void shouldHandleUnbalancedMessageSignatureBatchPairingAppendixSchemes(int messageCount, int signatureCount) throws IOException {
    //invalid/unbalanced input means number of messages * number of keys != number of signatures
    // Simulate invoking the file import method directly
    Platform.runLater(() -> {
      try {
        mainController.getSignatureVerificationControllerBenchmarking()
          .handleMessageBatch(createValidMessageBatch("validMessageBatch.txt", messageCount),
            verifyViewVal,
            signatureModelVal);
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    });

    List<Pair<int[], Boolean>> keyParams1 = new ArrayList<>();
    keyParams1.add(new Pair<>(new int[]{256, 256, 512}, false));
    keyParams1.add(new Pair<>(new int[]{512, 512, 1024}, true));

    // Import key or simulate importing key
    GenModelBenchmarking genModelBenchmarking = new GenModelBenchmarking();
    BenchmarkingUtility benchmarkingUtility = new BenchmarkingUtility();
    genModelBenchmarking.batchGenerateKeys(1, keyParams1,
      progress -> Platform.runLater(() -> {
        try {
          benchmarkingUtility.updateProgress(progress);
          benchmarkingUtility.updateProgressLabel(String.format("%.0f%%", progress * 100));
        } catch (NullPointerException e) {
        }
      }));
    WaitForAsyncUtils.waitForFxEvents();
    genModelBenchmarking.generateKeyBatch();
    genModelBenchmarking.exportPrivateKeyBatch();
    genModelBenchmarking.exportPublicKeyBatch();

    Optional<File> validKeyBatch = MainTestUtility.
      getFile("batchPublicKey", ".rsa");
    // Simulate invoking the file import method directly

    Platform.runLater(() -> {
      mainController.getSignatureVerificationControllerBenchmarking()
        .handleKeyBatch(validKeyBatch.get(), verifyViewVal, signatureModelVal);
    });

    WaitForAsyncUtils.waitForFxEvents();


    Platform.runLater(() -> {
      try {
        mainController.getSignatureVerificationControllerBenchmarking()
          .handleSignatureBatch(createSignatureBatch("signatureBatch.rsa", signatureCount), verifyViewVal, signatureModelVal);
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    });

    WaitForAsyncUtils.waitForFxEvents();

    robot.scroll(10, VerticalDirection.UP);
    ComboBox<String> signatureSchemeDropdown = robot.lookup("#signatureSchemeDropdown")
      .queryAs(ComboBox.class);
    robot.clickOn(signatureSchemeDropdown);
    robot.clickOn("PKCS#1 v1.5");
    ComboBox<String> hashFunctionDropdown = lookup("#hashFunctionDropdown").queryComboBox();
    robot.clickOn(hashFunctionDropdown);
    robot.clickOn("SHA-256");

    Platform.runLater(() -> {
      robot.clickOn("#verificationBenchmarkButton");
    });

    WaitForAsyncUtils.waitForFxEvents();

    assertNotNull((Node) robot.lookup(button -> button instanceof Button &&
        ((Button) button).getText().equals(ButtonType.OK.getText())).tryQuery().orElseThrow(
        () -> new AssertionError("Button with text '" + ButtonType.OK.getText() + "' not found.")
      ),
      "Failure popup box ok button should exist because number of messages and signature do not match");

  }

  /**
   * Provides pairs of message and signature counts that are expected to cause failures
   * during the verification benchmarking process due to unbalanced pairs for ISO message recovery schemes.
   *
   * @return Stream of arguments containing the number of messages and the number of signatures.
   */
  private static Stream<Arguments> provideMessageSignaturePairsForFailureRecovery() {
    return Stream.of(
      Arguments.of(2, 4),
      Arguments.of(4, 5)
    );
  }


  /**
   * Parameterized test that checks for the application's ability to handle cases where the number of non-recoverable messages
   * and signatures are unbalanced for ISO message recovery schemes. This mismatch is expected to cause a verification failure.
   *
   * @param messageCount   The number of non-recoverable messages to be used in the test.
   * @param signatureCount The number of signatures to be used in the test.
   * @throws IOException      If an I/O error occurs during the test.
   * @throws TimeoutException If the test takes longer than the maximum allowable time.
   */
  @ParameterizedTest
  @MethodSource("provideMessageSignaturePairsForFailureRecovery")
  void shouldHandleUnbalancedMessageSignatureBatchPairingISO_messageRecovery(int messageCount, int signatureCount) throws IOException, TimeoutException {
    //invalid/unbalanced input means number of non-recoverable messages != number of signatures
    // Simulate invoking the file import method directly
    Platform.runLater(() -> {
      try {
        mainController.getSignatureVerificationControllerBenchmarking()
          .handleMessageBatch(createValidMessageBatch("validMessageBatch.txt", messageCount),
            verifyViewVal,
            signatureModelVal);
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    });


    List<Pair<int[], Boolean>> keyParams1 = new ArrayList<>();
    keyParams1.add(new Pair<>(new int[]{256, 256, 512}, false));
    keyParams1.add(new Pair<>(new int[]{512, 512, 1024}, true));

    // Import key or simulate importing key
    GenModelBenchmarking genModelBenchmarking = new GenModelBenchmarking();
    BenchmarkingUtility benchmarkingUtility = new BenchmarkingUtility();
    genModelBenchmarking.batchGenerateKeys(1, keyParams1,
      progress -> Platform.runLater(() -> {
        try {
          benchmarkingUtility.updateProgress(progress);
          benchmarkingUtility.updateProgressLabel(String.format("%.0f%%", progress * 100));
        } catch (NullPointerException e) {
        }
      }));
    WaitForAsyncUtils.waitForFxEvents();
    genModelBenchmarking.generateKeyBatch();
    genModelBenchmarking.exportPrivateKeyBatch();
    genModelBenchmarking.exportPublicKeyBatch();

    Optional<File> validKeyBatch = MainTestUtility.
      getFile("batchPublicKey", ".rsa");
    // Simulate invoking the file import method directly

    Platform.runLater(() -> {
      mainController.getSignatureVerificationControllerBenchmarking()
        .handleKeyBatch(validKeyBatch.get(), verifyViewVal, signatureModelVal);
    });

    WaitForAsyncUtils.waitForFxEvents();


    Platform.runLater(() -> {
      try {
        mainController.getSignatureVerificationControllerBenchmarking()
          .handleSignatureBatch(createSignatureBatch("signatureBatch.rsa", signatureCount),
            verifyViewVal, signatureModelVal);
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    });

    WaitForAsyncUtils.waitForFxEvents();

    robot.scroll(10, VerticalDirection.UP);
    ComboBox<String> signatureSchemeDropdown = robot.lookup("#signatureSchemeDropdown")
      .queryAs(ComboBox.class);
    robot.clickOn(signatureSchemeDropdown);
    robot.clickOn("ISO\\IEC 9796-2 Scheme 1");
    ComboBox<String> hashFunctionDropdown = lookup("#hashFunctionDropdown").queryComboBox();
    robot.clickOn(hashFunctionDropdown);
    robot.clickOn("SHA-256");

    Platform.runLater(() -> {
      robot.clickOn("#verificationBenchmarkButton");
    });

    WaitForAsyncUtils.waitForFxEvents();

    assertNotNull((Node) robot.lookup(button -> button instanceof Button &&
        ((Button) button).getText().equals(ButtonType.OK.getText())).tryQuery().orElseThrow(
        () -> new AssertionError("Button with text '" + ButtonType.OK.getText() + "' not found.")
      ),
      "Failure popup box ok button should exist because number of messages and signature do not match");

  }


}
