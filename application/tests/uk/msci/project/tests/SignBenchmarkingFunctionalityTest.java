package uk.msci.project.tests;

import com.jfoenix.controls.JFXTabPane;
import javafx.application.Platform;
import javafx.geometry.VerticalDirection;
import javafx.scene.Node;
import javafx.scene.control.*;
import javafx.scene.image.ImageView;
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


/**
 * This class provides automated UI tests for the signature generation feature in the Signature
 * Scheme benchmarking application. It employs the TestFX framework to simulate user interactions with the
 * signing view and ensures that all aspects of the UI are functioning as expected.
 *
 * <p>Each test method is designed to be independent, setting up the necessary preconditions and
 * cleaning up afterward to avoid side effects that could affect other tests.
 *
 * @see Test
 * @see ApplicationExtension
 * @see FxRobot
 */
public class SignBenchmarkingFunctionalityTest extends ApplicationTest {

  private FxRobot robot;

  private MainController mainController;

  private SignView signViewVal;

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
   * Prepares the application's UI for the sign view before each test. It deletes files with a
   * specific suffix to ensure a clean state and navigates to the sign view by simulating a button
   * click.
   */
  @BeforeEach
  public void setup() throws IllegalAccessException, NoSuchFieldException {

    String fileNamePrefix = "testFile";
    String fileExtension = "txt";
    deleteFilesWithSuffix(fileNamePrefix, fileExtension);
    robot = new FxRobot();
    robot.clickOn("#signDocumentButton");
    WaitForAsyncUtils.waitForFxEvents();

    Field signViewField = SignatureCreationControllerBenchmarking.class.getDeclaredField("signView");
    signViewField.setAccessible(true);
    signViewVal = (SignView) signViewField.get(mainController.getSignatureCreationControllerBenchmarking());

    Field signatureModelField = SignatureCreationControllerBenchmarking.class.getDeclaredField("signatureModel");
    signatureModelField.setAccessible(true);
    signatureModelVal = (SignatureModelBenchmarking)
      signatureModelField.get(mainController.getSignatureCreationControllerBenchmarking());

  }

  /**
   * Creates an invalid message batch for testing purposes.
   *
   * @param filename The  name of the file.
   * @param type     The type of invalid content (e.g., "Incorrect number of messages", "Contains empty lines after non-empty lines").
   * @return The created file.
   * @throws IOException If an I/O error occurs.
   */
  public static File createInvalidMessageBatch(String filename, String type) throws IOException {
    File file = new File(filename);
    try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
      switch (type) {
        case "Incorrect number of messages":

          for (int i = 0; i < 3; i++) {
            writer.write("Message " + i);
            writer.newLine();
          }
          break;
        case "Contains empty lines after non-empty lines":
          // Write valid messages followed by an empty line
          for (int i = 0; i < 5; i++) {
            writer.write("Message " + i);
            writer.newLine();
          }
          writer.newLine(); // Add an empty line to simulate improper formatting
          break;
        case "Contains empty lines in the middle":
          // Write some valid messages, then an empty line, and then more valid messages
          for (int i = 0; i < 3; i++) {
            writer.write("Message " + i);
            writer.newLine();
          }
          writer.newLine(); // Insert an empty line
          for (int i = 3; i < 5; i++) {
            writer.write("Message " + i);
            writer.newLine();
          }
          break;
        default:
          // Default content if no specific type is matched
          writer.write("Default content");
      }
    }
    return file;
  }

  /**
   * Creates a file with a valid message batch for testing.
   * The file will contain the specified number of messages, each on a new line.
   *
   * @param filename    The name of the file to be created.
   * @param numMessages The number of messages to be included in the file.
   * @return A {@link File} object representing the created file.
   * @throws IOException If there is an error in file operations.
   */
  static File createValidMessageBatch(String filename, int numMessages) throws IOException {
    File file = new File(filename);
    try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
      for (int i = 0; i < numMessages; i++) {
        writer.write("Message " + i);
        writer.newLine();
      }
    }
    return file;
  }


  /**
   * Verifies the presence of all necessary UI components within the sign view.
   */
  @Test
  void shouldContainUIComponents() {
    // Verifying essential text fields
    assertNotNull(robot.lookup("#numMessageField").queryAs(TextField.class),
      "Number of messages (trials) field should exist.");
    assertNotNull(robot.lookup("#messageBatchField").queryAs(TextField.class),
      "Message batch field should exist.");
    assertNotNull(robot.lookup("#keyField").queryAs(TextField.class),
      "Private key batch field should exist.");

    // Verifying buttons
    assertNotNull(robot.lookup("#importTextBatchBtn").queryAs(Button.class),
      "Import text batch button should exist.");
    assertNotNull(robot.lookup("#importKeyBatchButton").queryAs(Button.class),
      "Import key batch button should exist.");
    assertNotNull(robot.lookup("#SigBenchmarkButton").queryAs(Button.class),
      "Start Signature Benchmarking button should exist.");

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
   * Ensures that the application properly notifies the user when the provided private key batch is
   * corrupted or otherwise unreadable.
   *
   * @throws IOException            if there is an issue handling the key files.
   */
  @Test
  void shouldHandleErrorWhenCorruptedKeyBatch() throws IOException {
    // Import key or simulate importing key

    FileHandle.exportToFile("corruptKeyBatch.rsa", "awsedfrgttgdfrs");
    Optional<File> corruptKeyBatch = MainTestUtility.
      getFile("corruptKey", ".rsa");
    // Simulate invoking the file import method directly
    Platform.runLater(() -> {
      mainController.getSignatureCreationControllerBenchmarking()
        .handleKeyBatch(corruptKeyBatch.get(), signViewVal, signatureModelVal);
    });

    WaitForAsyncUtils.waitForFxEvents();
    assertNotNull((Node) robot.lookup(button -> button instanceof Button &&
        ((Button) button).getText().equals(ButtonType.OK.getText())).tryQuery().orElseThrow(
        () -> new AssertionError("Button with text '" + ButtonType.OK.getText() + "' not found.")
      ),
      "Failure popup box ok button should exist.");

  }

  /**
   * Provides sets of valid key parameters for use in parameterised tests of key batch import.
   *
   * @return A stream of arguments, each representing a set of key parameters and an associated boolean flag.
   */
  private static Stream<Arguments> validKeyParams() {
    List<Pair<int[], Boolean>> keyParams1 = new ArrayList<>();
    keyParams1.add(new Pair<>(new int[]{256, 256, 512}, false));
    keyParams1.add(new Pair<>(new int[]{512, 512, 1024}, true));

    List<Pair<int[], Boolean>> keyParams2 = new ArrayList<>();
    keyParams2.add(new Pair<>(new int[]{1024, 1024}, false));
    keyParams2.add(new Pair<>(new int[]{768, 768, 1536}, true));
    keyParams2.add(new Pair<>(new int[]{1536, 1536}, true));
    keyParams2.add(new Pair<>(new int[]{512, 512}, true));
    return Stream.of(
      Arguments.of(keyParams1),
      Arguments.of(keyParams2)
    );
  }


  /**
   * Handles the import of a valid key batch. It checks if the UI components update correctly
   * upon a successful import and also tests the UI response when the import is cancelled.
   *
   * @param keyParams The key parameters to use for generating and importing the key batch.
   * @throws IOException if an I/O error occurs during file handling.
   */
  @ParameterizedTest
  @MethodSource("validKeyParams")
  void shouldHandleValidKeyBatchImport(List<Pair<int[], Boolean>> keyParams) throws IOException {


    // Import key or simulate importing key
    GenModelBenchmarking genModelBenchmarking = new GenModelBenchmarking();
    BenchmarkingUtility benchmarkingUtility = new BenchmarkingUtility();
    genModelBenchmarking.batchGenerateKeys(1, keyParams,
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
      getFile("batchKey", ".rsa");
    // Simulate invoking the file import method directly

    Platform.runLater(() -> {
      mainController.getSignatureCreationControllerBenchmarking()
        .handleKeyBatch(validKeyBatch.get(), signViewVal, signatureModelVal);
    });


    WaitForAsyncUtils.waitForFxEvents();


    Platform.runLater(() -> {
      assertTrue(robot.lookup("#checkmarkImage").queryAs(ImageView.class).isVisible());
      assertFalse(robot.lookup("#importKeyBatchButton").queryAs(Button.class).isVisible());
      assertTrue(robot.lookup("#cancelImportKeyButton").queryAs(Button.class).isVisible());
    });


    WaitForAsyncUtils.waitForFxEvents();

    Platform.runLater(() -> {
      robot.clickOn(robot.lookup("#cancelImportKeyButton").queryAs(Button.class));
    });


    WaitForAsyncUtils.waitForFxEvents();


    Platform.runLater(() -> {
      assertFalse(robot.lookup("#checkmarkImage").queryAs(ImageView.class).isVisible());
      assertTrue(robot.lookup("#importKeyBatchButton").queryAs(Button.class).isVisible());
      assertFalse(robot.lookup("#cancelImportKeyButton").queryAs(Button.class).isVisible());
    });

    // Ensure all final assertions are processed
    WaitForAsyncUtils.waitForFxEvents();


  }

  /**
   * Provides parameters for generating invalid message batches to simulate various error conditions.
   *
   * @return A stream of arguments where each argument consists of a file with an invalid message batch
   * and the expected number of messages that should have been in the batch.
   * @throws IOException if an error occurs while creating the test files.
   */
  private static Stream<Arguments> invalidMessageBatchParams() throws IOException {
    File wrongMessageCountFile = createInvalidMessageBatch("wrongMessageCount.txt", "Incorrect number of messages");
    File improperlyFormattedFile = createInvalidMessageBatch("improperlyFormatted,txt", "Contains empty lines after non-empty lines");
    File emptyLinesInMiddleFile = createInvalidMessageBatch("emptyLinesInMiddle.txt", "Contains empty lines in the middle");

    // Assuming the expected number of messages is 5 for demonstration
    return Stream.of(
      Arguments.of(wrongMessageCountFile, 5),
      Arguments.of(improperlyFormattedFile, 5),
      Arguments.of(emptyLinesInMiddleFile, 5)
    );
  }

  @ParameterizedTest
  @MethodSource("invalidMessageBatchParams")
  void shouldHandleInvalidMessageBatchImport(File invalidFile, int expectedNumMessages) throws Exception {
    // Simulate setting the number of messages in the UI
    robot.clickOn("#numMessageField");
    robot.write(String.valueOf(expectedNumMessages));
    WaitForAsyncUtils.waitForFxEvents();

    // Simulate invoking the file import method directly
    Platform.runLater(() -> {
      mainController.getSignatureCreationControllerBenchmarking()
        .handleMessageBatch(invalidFile, signViewVal, signatureModelVal);
    });
    WaitForAsyncUtils.waitForFxEvents();

    WaitForAsyncUtils.waitForFxEvents();
    assertNotNull((Node) robot.lookup(button -> button instanceof Button &&
        ((Button) button).getText().equals(ButtonType.OK.getText())).tryQuery().orElseThrow(
        () -> new AssertionError("Button with text '" + ButtonType.OK.getText() + "' not found.")
      ),
      "Failure popup box ok button should exist.");

  }

  /**
   * Provides parameters for generating valid message batches to test the normal functioning of message batch imports.
   *
   * @return A stream of arguments where each argument consists of a file with a valid message batch
   *         and the number of messages contained in that batch.
   * @throws IOException if an error occurs while creating the test files.
   */
  private static Stream<Arguments> validMessageBatchParams() throws IOException {
    File validMessageBatchFile = createValidMessageBatch("validMessageBatch.txt", 5);
    int expectedNumMessages = 5; // This should match the number of messages in your valid batch

    return Stream.of(
      Arguments.of(validMessageBatchFile, expectedNumMessages)
    );
  }


  /**
   * Handles the import of a valid message batch. It verifies the correct update of UI components
   * and functionality of cancel buttons when a valid message batch is imported.
   *
   * @param validFile The file containing the valid message batch.
   * @param expectedNumMessages The expected number of messages that are contained in the batch.
   * @throws Exception if an error occurs during the test execution.
   */
  @ParameterizedTest
  @MethodSource("validMessageBatchParams")
  void shouldHandleValidMessageBatchImport(File validFile, int expectedNumMessages) throws Exception {

    // Simulate setting the number of messages in the UI
    robot.clickOn("#numMessageField");
    robot.write(String.valueOf(expectedNumMessages));
    WaitForAsyncUtils.waitForFxEvents();

    // Simulate invoking the file import method directly
    Platform.runLater(() -> {
      mainController.getSignatureCreationControllerBenchmarking()
        .handleMessageBatch(validFile, signViewVal, signatureModelVal);
    });
    WaitForAsyncUtils.waitForFxEvents();


    Platform.runLater(() -> {
      assertTrue(robot.lookup("#textFileCheckmarkImage").queryAs(ImageView.class).isVisible());
      assertFalse(robot.lookup("#importTextBatchBtn").queryAs(Button.class).isVisible());
      assertTrue(robot.lookup("#cancelImportTextBatchButton").queryAs(Button.class).isVisible());
    });


    WaitForAsyncUtils.waitForFxEvents();

    Platform.runLater(() -> {
      robot.clickOn(robot.lookup("#cancelImportTextBatchButton").queryAs(Button.class));
    });


    WaitForAsyncUtils.waitForFxEvents();


    Platform.runLater(() -> {
      assertFalse(robot.lookup("#textFileCheckmarkImage").queryAs(ImageView.class).isVisible());
      assertTrue(robot.lookup("#importTextBatchBtn").queryAs(Button.class).isVisible());
      assertFalse(robot.lookup("#cancelImportTextBatchButton").queryAs(Button.class).isVisible());
    });

    WaitForAsyncUtils.waitForFxEvents();
  }

  /**
   * Verifies the options available in the hash function dropdown based on the selected parameter.
   * This test checks if the correct hash function options are displayed when "Standard",
   * "Provably Secure", and "Custom" radio buttons are selected.
   */
  @Test
  void testHashFunctionDropdownOptions() {
    // Click on the "Standard" radio button and check options
    robot.clickOn("#standardParametersRadio");
    verifyComboBoxItems("#hashFunctionDropdown", "SHA-256", "SHA-512");

    // Click on the "Provably Secure" radio button and check options
    robot.clickOn("#provablySecureParametersRadio");
    verifyComboBoxItems("#hashFunctionDropdown", "SHA-256 with MGF1", "SHA-512 with MGF1", "SHAKE-128", "SHAKE-256");

    // Click on the "Custom" radio button and check options
    robot.clickOn("#customParametersRadio");
    verifyComboBoxItems("#hashFunctionDropdown", "SHA-256 with MGF1", "SHA-512 with MGF1", "SHAKE-128", "SHAKE-256");
  }

  /**
   * Verifies the items in a ComboBox.
   *
   * @param comboBoxQuery The query string to find the ComboBox.
   * @param items         The expected items in the ComboBox.
   */
  private void verifyComboBoxItems(String comboBoxQuery, String... items) {
    ComboBox<String> comboBox = lookup(comboBoxQuery).queryComboBox();
    for (String item : items) {
      assertTrue(comboBox.getItems().contains(item), "ComboBox should contain: " + item);
    }
  }

  /**
   * Tests the visibility of the hash output size field based on the selected hash function.
   * The field should be visible for provably secure and custom hash functions and hidden otherwise.
   */
  @Test
  void testHashOutputSizeFieldVisibility() {
    selectHashFunctionAndCheckVisibility("SHA-256 with MGF1", true);
    selectHashFunctionAndCheckVisibility("SHA-512 with MGF1", true);
    selectHashFunctionAndCheckVisibility("SHAKE-128", true);
    selectHashFunctionAndCheckVisibility("SHAKE-256", true);
  }

  /**
   * Selects a hash function in the dropdown and checks the visibility of the hash output size field.
   *
   * @param hashFunction       The hash function to be selected.
   * @param expectedVisibility Expected visibility of the hash output size field.
   */
  private void selectHashFunctionAndCheckVisibility(String hashFunction, boolean expectedVisibility) {
    // Select the hash function from the dropdown
    Platform.runLater(() -> {
      robot.clickOn("#customParametersRadio");
    });
    WaitForAsyncUtils.waitForFxEvents();
    ComboBox<String> hashFunctionDropdown = lookup("#hashFunctionDropdown").queryComboBox();

    Platform.runLater(() -> {
      robot.clickOn(hashFunctionDropdown);
    });
    WaitForAsyncUtils.waitForFxEvents();

    Platform.runLater(() -> {
      robot.clickOn(hashFunction);
    });
    WaitForAsyncUtils.waitForFxEvents();

    // Cast the result of the query to TextArea
    TextArea hashOutputSizeField = (TextArea) lookup("#hashOutputSizeField").query();
    if (expectedVisibility) {
      assertTrue(hashOutputSizeField.isVisible(), "HashOutputSizeField should be visible for " + hashFunction);
    } else {
      assertFalse(hashOutputSizeField.isVisible(), "HashOutputSizeField should not be visible for " + hashFunction);
    }
  }

  /**
   * Tests the application's behavior when attempting to enable comparison benchmarking which
   * is not permitted to be enabled in normal benchmarking mode.
   */
  @Test
  void shouldHandleAttemptToSwitchOnComparisonBenchmarking() {
    ToggleSwitch crossParameterBenchmarkingModeToggle = robot.lookup
      ("#crossParameterBenchmarkingModeToggle").queryAs(ToggleSwitch.class);
    assertFalse(crossParameterBenchmarkingModeToggle.isSelected());


    Platform.runLater(() -> {
      robot.clickOn(crossParameterBenchmarkingModeToggle);
    });
    WaitForAsyncUtils.waitForFxEvents();
    assertNotNull((Node) robot.lookup(button -> button instanceof Button &&
        ((Button) button).getText().equals(ButtonType.OK.getText())).tryQuery().orElseThrow(
        () -> new AssertionError("Button with text '" + ButtonType.OK.getText() + "' not found.")
      ),
      "Failure popup box ok button should exist.");
    assertFalse(crossParameterBenchmarkingModeToggle.isSelected());

  }

  /**
   * Tests the application's response when attempting to sign text without providing a key batch.
   *
   * @throws IOException if there is an issue handling the message batch file.
   */
  @Test
  void shouldHandleErrorWhenNoKeyBatchProvided() throws IOException {
    // Simulate setting the number of messages in the UI
    robot.clickOn("#numMessageField");
    robot.write(String.valueOf(5));
    WaitForAsyncUtils.waitForFxEvents();

    // Simulate invoking the file import method directly
    Platform.runLater(() -> {
      try {
        mainController.getSignatureCreationControllerBenchmarking()
          .handleMessageBatch(createValidMessageBatch("validMessageBatch.txt", 5),
            signViewVal,
            signatureModelVal);
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    });
    WaitForAsyncUtils.waitForFxEvents();


    ComboBox<String> signatureSchemeDropdown = robot.lookup("#signatureSchemeDropdown")
      .queryAs(ComboBox.class);
    robot.clickOn(signatureSchemeDropdown);
    robot.clickOn("PKCS#1 v1.5");
    ComboBox<String> hashFunctionDropdown = lookup("#hashFunctionDropdown").queryComboBox();
    robot.clickOn(hashFunctionDropdown);
    robot.clickOn("SHA-256");
    robot.scroll(10, VerticalDirection.UP);
    robot.clickOn("#SigBenchmarkButton");
    assertNotNull((Node) robot.lookup(button -> button instanceof Button &&
        ((Button) button).getText().equals(ButtonType.OK.getText())).tryQuery().orElseThrow(
        () -> new AssertionError("Button with text '" + ButtonType.OK.getText() + "' not found.")
      ),
      "Failure popup box ok button should exist.");
  }

  /**
   * Handles errors when no message batch is provided for the signature creation process.
   * This test ensures that the application properly notifies the user of the missing message batch.
   *
   * @throws IOException if there is an issue with file handling during the test.
   */
  @Test
  void shouldHandleErrorWhenNoMessageBatchProvided() throws IOException {
    // Simulate setting the number of messages in the UI
    robot.clickOn("#numMessageField");
    robot.write(String.valueOf(5));
    WaitForAsyncUtils.waitForFxEvents();


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
      getFile("batchKey", ".rsa");
    // Simulate invoking the file import method directly

    Platform.runLater(() -> {
      mainController.getSignatureCreationControllerBenchmarking()
        .handleKeyBatch(validKeyBatch.get(), signViewVal, signatureModelVal);
    });

    WaitForAsyncUtils.waitForFxEvents();


    ComboBox<String> signatureSchemeDropdown = robot.lookup("#signatureSchemeDropdown")
      .queryAs(ComboBox.class);
    robot.clickOn(signatureSchemeDropdown);
    robot.clickOn("PKCS#1 v1.5");
    ComboBox<String> hashFunctionDropdown = lookup("#hashFunctionDropdown").queryComboBox();
    robot.clickOn(hashFunctionDropdown);
    robot.clickOn("SHA-256");
    robot.scroll(10, VerticalDirection.UP);
    robot.clickOn("#SigBenchmarkButton");
    assertNotNull((Node) robot.lookup(button -> button instanceof Button &&
        ((Button) button).getText().equals(ButtonType.OK.getText())).tryQuery().orElseThrow(
        () -> new AssertionError("Button with text '" + ButtonType.OK.getText() + "' not found.")
      ),
      "Failure popup box ok button should exist.");
  }

  /**
   * Handles errors when no signature scheme is selected.
   * This test checks the application's response to the absence of a selected signature scheme.
   *
   * @throws IOException if there is an issue with file handling during the test.
   */
  @Test
  void shouldHandleErrorWhenNoSchemeSelected() throws IOException {
    // Simulate setting the number of messages in the UI
    robot.clickOn("#numMessageField");
    robot.write(String.valueOf(5));
    WaitForAsyncUtils.waitForFxEvents();

    // Simulate invoking the file import method directly
    Platform.runLater(() -> {
      try {
        mainController.getSignatureCreationControllerBenchmarking()
          .handleMessageBatch(createValidMessageBatch("validMessageBatch.txt", 5),
            signViewVal,
            signatureModelVal);
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    });
    WaitForAsyncUtils.waitForFxEvents();
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
      getFile("batchKey", ".rsa");
    // Simulate invoking the file import method directly

    Platform.runLater(() -> {
      mainController.getSignatureCreationControllerBenchmarking()
        .handleKeyBatch(validKeyBatch.get(), signViewVal, signatureModelVal);
    });

    WaitForAsyncUtils.waitForFxEvents();

    ComboBox<String> hashFunctionDropdown = lookup("#hashFunctionDropdown").queryComboBox();
    robot.clickOn(hashFunctionDropdown);
    robot.clickOn("SHA-256");
    robot.scroll(10, VerticalDirection.UP);
    robot.clickOn("#SigBenchmarkButton");
    assertNotNull((Node) robot.lookup(button -> button instanceof Button &&
        ((Button) button).getText().equals(ButtonType.OK.getText())).tryQuery().orElseThrow(
        () -> new AssertionError("Button with text '" + ButtonType.OK.getText() + "' not found.")
      ),
      "Failure popup box ok button should exist.");
  }

  /**
   * Handles errors when no hash function is provided.
   * This test ensures the application displays an appropriate error message when a hash function is not selected.
   *
   * @throws IOException if there is an issue with file handling during the test.
   */
  @Test
  void shouldHandleErrorWhenNoHashFunctionProvided() throws IOException {
    // Simulate setting the number of messages in the UI
    robot.clickOn("#numMessageField");
    robot.write(String.valueOf(5));
    WaitForAsyncUtils.waitForFxEvents();

    // Simulate invoking the file import method directly
    Platform.runLater(() -> {
      try {
        mainController.getSignatureCreationControllerBenchmarking()
          .handleMessageBatch(createValidMessageBatch("validMessageBatch.txt", 5),
            signViewVal,
            signatureModelVal);
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    });
    WaitForAsyncUtils.waitForFxEvents();
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
      getFile("batchKey", ".rsa");
    // Simulate invoking the file import method directly

    Platform.runLater(() -> {
      mainController.getSignatureCreationControllerBenchmarking()
        .handleKeyBatch(validKeyBatch.get(), signViewVal, signatureModelVal);
    });

    WaitForAsyncUtils.waitForFxEvents();


    ComboBox<String> signatureSchemeDropdown = robot.lookup("#signatureSchemeDropdown")
      .queryAs(ComboBox.class);
    robot.clickOn(signatureSchemeDropdown);
    robot.clickOn("PKCS#1 v1.5");

    robot.scroll(10, VerticalDirection.UP);
    robot.clickOn("#SigBenchmarkButton");
    assertNotNull((Node) robot.lookup(button -> button instanceof Button &&
        ((Button) button).getText().equals(ButtonType.OK.getText())).tryQuery().orElseThrow(
        () -> new AssertionError("Button with text '" + ButtonType.OK.getText() + "' not found.")
      ),
      "Failure popup box ok button should exist.");
  }

  /**
   * Handles errors when no custom hash output size is provided when the custom hash function size is selected.
   * The test checks the application's response to the absence of a specified hash output size.
   *
   * @throws IOException if there is an issue with file handling during the test.
   */
  @Test
  void shouldHandleErrorWhenNoCustomHashOutputIsProvided() throws IOException {

    String[] customHashFunctions = new String[]{
      "SHA-256 with MGF1",
      "SHA-512 with MGF1",
      "SHAKE-128",
      "SHAKE-256"
    };
    // Simulate setting the number of messages in the UI
    robot.clickOn("#numMessageField");
    robot.write(String.valueOf(5));
    WaitForAsyncUtils.waitForFxEvents();

    // Simulate invoking the file import method directly
    Platform.runLater(() -> {
      try {
        mainController.getSignatureCreationControllerBenchmarking()
          .handleMessageBatch(createValidMessageBatch("validMessageBatch.txt", 5),
            signViewVal,
            signatureModelVal);
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    });
    WaitForAsyncUtils.waitForFxEvents();
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
      getFile("batchKey", ".rsa");
    // Simulate invoking the file import method directly

    Platform.runLater(() -> {
      mainController.getSignatureCreationControllerBenchmarking()
        .handleKeyBatch(validKeyBatch.get(), signViewVal, signatureModelVal);
    });

    WaitForAsyncUtils.waitForFxEvents();


    ComboBox<String> signatureSchemeDropdown = robot.lookup("#signatureSchemeDropdown")
      .queryAs(ComboBox.class);
    robot.clickOn(signatureSchemeDropdown);
    robot.clickOn("PKCS#1 v1.5");
    robot.scroll(10, VerticalDirection.UP);
    ComboBox<String> hashFunctionDropdown = lookup("#hashFunctionDropdown").queryComboBox();
    Platform.runLater(() -> {
      robot.clickOn("#customParametersRadio");
    });
    WaitForAsyncUtils.waitForFxEvents();
    for (String hashFunction : customHashFunctions) {
      // Selecting a hash function that requires a custom output size

      Platform.runLater(() -> {
        robot.clickOn(hashFunctionDropdown);
      });
      WaitForAsyncUtils.waitForFxEvents();

      Platform.runLater(() -> {
        robot.clickOn(hashFunction);
      });
      WaitForAsyncUtils.waitForFxEvents();

      Platform.runLater(() -> {
        // Attempting to perform the operation without providing the custom output size
        robot.clickOn("#SigBenchmarkButton");
      });
      WaitForAsyncUtils.waitForFxEvents();

      Platform.runLater(() -> {
        // Verify that an error message is displayed
        assertNotNull((Node) robot.lookup(button -> button instanceof Button &&
          ((Button) button).getText().equals(ButtonType.OK.getText())).tryQuery().orElseThrow(
          () -> new AssertionError("Error popup box OK button not found for " + hashFunction)
        ), "Failure popup box OK button should exist for " + hashFunction);
        MainTestUtility.clickOnDialogButton(robot, ButtonType.OK);

      });


      WaitForAsyncUtils.waitForFxEvents();
    }
  }

  /**
   * Displays benchmarking results for valid input scenarios.
   * This test ensures that the application correctly processes and displays the results of the benchmarking process.
   *
   * @throws IOException      if there is an issue with file handling during the test.
   * @throws TimeoutException if the test takes longer than the maximum allowable time.
   */
  @Test
  void shouldDisplayResultsOnValidInputs() throws IOException, TimeoutException {
    // Simulate setting the number of messages in the UI
    robot.clickOn("#numMessageField");
    robot.write(String.valueOf(5));
    WaitForAsyncUtils.waitForFxEvents();

    // Simulate invoking the file import method directly
    Platform.runLater(() -> {
      try {
        mainController.getSignatureCreationControllerBenchmarking()
          .handleMessageBatch(createValidMessageBatch("validMessageBatch.txt", 5),
            signViewVal,
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
      getFile("batchKey", ".rsa");
    // Simulate invoking the file import method directly

    Platform.runLater(() -> {
      mainController.getSignatureCreationControllerBenchmarking()
        .handleKeyBatch(validKeyBatch.get(), signViewVal, signatureModelVal);
    });

    WaitForAsyncUtils.waitForFxEvents();


    ComboBox<String> signatureSchemeDropdown = robot.lookup("#signatureSchemeDropdown")
      .queryAs(ComboBox.class);
    robot.clickOn(signatureSchemeDropdown);
    robot.clickOn("PKCS#1 v1.5");
    ComboBox<String> hashFunctionDropdown = lookup("#hashFunctionDropdown").queryComboBox();
    robot.clickOn(hashFunctionDropdown);
    robot.clickOn("SHA-256");
    robot.scroll(10, VerticalDirection.UP);
    Platform.runLater(() -> {
      robot.clickOn("#SigBenchmarkButton");
    });

    WaitForAsyncUtils.waitForFxEvents();


    ProgressBar progressBar = robot.lookup("#progressBar").queryAs(ProgressBar.class);
    WaitForAsyncUtils.waitForFxEvents();
    WaitForAsyncUtils.waitFor(1, TimeUnit.SECONDS, () -> progressBar.getProgress() >= 1);


    // Check that the results title label is displayed and correct
    Platform.runLater(() -> {
      Label resultsTitleLabel = robot.lookup("#resultsLabel").queryAs(Label.class);
      assertEquals("Benchmarking Results for Signature Creation (PKCS#1 v1.5 Signature Scheme-SHA-256)", resultsTitleLabel.getText());
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


      robot.clickOn(exportBenchmarkingResultsBtn);
      waitForExportDialogToShow(robot);
      robot.clickOn(robot
        .from(((Stage) robot.window("Export")).getScene().getRoot())
        .lookup(".button")
        .match(hasText("OK"))
        .queryButton());


      Optional<File> benchmarkingResultsFile = MainTestUtility.getFile(
        "Benchmarking Results for Signature Creation (PKCS#1 v1.5 Signature Scheme)_" + keyLengths[i] + "bit", ".csv");
      assertTrue(benchmarkingResultsFile.isPresent(), "Expected export file not found.");
      assertTrue(benchmarkingResultsFile.get().exists(), "Exported file should exist.");

      // Verify that the statistics table is populated
      TableView<?> tableView = robot.lookup("#tableView").queryAs(TableView.class);
      assertFalse(tableView.getItems().isEmpty(), "The table should have data.");


    }


    // Check for the presence of the export buttons and their texts
    Button signatureBatchBtn = robot.lookup("#exportSignatureBatchBtn").queryAs(Button.class);

    // Verify that buttons are visible and then simulate clicks
    assertTrue(signatureBatchBtn.isVisible(), "Export signature batch button should be visible.");


    robot.clickOn(signatureBatchBtn);
    waitForExportDialogToShow(robot);
    robot.clickOn(robot
      .from(((Stage) robot.window("Export")).getScene().getRoot())
      .lookup(".button")
      .match(hasText("OK"))
      .queryButton());
    waitForExportDialogToShow(robot);

    //logic to verify that the keys were actually exported by checking for existence of signature batch file
    //if there are multiple signature files then the files are exported with an increasing number suffix
    // getFile retrieves the most recently exported file i.e., the highest number suffix

    Optional<File> signatureBatchFile = MainTestUtility.getFile("signatureBatch", ".rsa");
    assertTrue(signatureBatchFile.isPresent(), "Expected exported file not found.");
    assertTrue(signatureBatchFile.get().exists(), "Exported file should exist.");

  }


  /**
   * This test checks the application's response to invalid custom hash output values provided by the
   * user. A valid input is fraction under 1 e.g., 1/2.
   *
   * @throws IOException if there is an issue with file handling during the test.
   */
  @Test
  void shouldHandleCustomHashOutput() throws IOException {
    String hashFunction = "SHA-256 with MGF1"; // Testing for one hash function for simplicity
    String[] invalidInputs = {"", "a/b", "1/", "/1", "test", "67", "2/1", "1.5/2", "10/10", "-1/2", "0/1", "!@#$%^&*()"};

    // Simulate setting the number of messages in the UI
    robot.clickOn("#numMessageField");
    robot.write(String.valueOf(5));
    WaitForAsyncUtils.waitForFxEvents();

    // Simulate invoking the file import method directly
    Platform.runLater(() -> {
      try {
        mainController.getSignatureCreationControllerBenchmarking()
          .handleMessageBatch(createValidMessageBatch("validMessageBatch.txt", 5),
            signViewVal,
            signatureModelVal);
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    });
    WaitForAsyncUtils.waitForFxEvents();
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
      getFile("batchKey", ".rsa");
    // Simulate invoking the file import method directly

    Platform.runLater(() -> {
      mainController.getSignatureCreationControllerBenchmarking()
        .handleKeyBatch(validKeyBatch.get(), signViewVal, signatureModelVal);
    });

    WaitForAsyncUtils.waitForFxEvents();


    ComboBox<String> signatureSchemeDropdown = robot.lookup("#signatureSchemeDropdown")
      .queryAs(ComboBox.class);
    robot.clickOn(signatureSchemeDropdown);
    robot.clickOn("PKCS#1 v1.5");
    robot.scroll(10, VerticalDirection.UP);

    WaitForAsyncUtils.waitForFxEvents();


    Platform.runLater(() -> {
      robot.clickOn("#customParametersRadio");
    });
    ComboBox<String> hashFunctionDropdown = lookup("#hashFunctionDropdown").queryComboBox();

    WaitForAsyncUtils.waitForFxEvents();


    Platform.runLater(() -> {
      robot.clickOn(hashFunctionDropdown);
    });
    WaitForAsyncUtils.waitForFxEvents();

    Platform.runLater(() -> {
      robot.clickOn(hashFunction);
    });
    WaitForAsyncUtils.waitForFxEvents();

    TextArea hashOutputSizeField = lookup("#hashOutputSizeField").queryAs(TextArea.class);

    for (String input : invalidInputs) {
      // Enter each invalid input and attempt to perform the operation
      Platform.runLater(() -> {
        hashOutputSizeField.clear();
        hashOutputSizeField.setText(input);
        robot.clickOn("#SigBenchmarkButton");
      });
      WaitForAsyncUtils.waitForFxEvents();

      // Verify that an error message is displayed
      Platform.runLater(() -> {
        assertNotNull((Node) robot.lookup(button -> button instanceof Button &&
          ((Button) button).getText().equals(ButtonType.OK.getText())).tryQuery().orElseThrow(
          () -> new AssertionError("Error popup box OK button not found for " + hashFunction)
        ), "Failure popup box OK button should exist for " + hashFunction);
        MainTestUtility.clickOnDialogButton(robot, ButtonType.OK);


      });

      WaitForAsyncUtils.waitForFxEvents();
    }
  }

  /**
   * Tests the recovery options for ISO/IEC 9796-2 Scheme 1 in the signature benchmarking process.
   * Verifies the correctness of the benchmarking results and the availability of export options
   * for signature batches and non-recoverable messages.
   *
   * @throws IOException      if there is an issue handling files during the test.
   * @throws TimeoutException if the test execution exceeds the allowable duration.
   */
  @Test
  void testISOrecoveryOptions() throws IOException, TimeoutException {
    // Simulate setting the number of messages in the UI
    robot.clickOn("#numMessageField");
    robot.write(String.valueOf(5));
    WaitForAsyncUtils.waitForFxEvents();

    // Simulate invoking the file import method directly
    Platform.runLater(() -> {
      try {
        mainController.getSignatureCreationControllerBenchmarking()
          .handleMessageBatch(createValidMessageBatch("validMessageBatch.txt", 5),
            signViewVal,
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
      getFile("batchKey", ".rsa");
    // Simulate invoking the file import method directly

    Platform.runLater(() -> {
      mainController.getSignatureCreationControllerBenchmarking()
        .handleKeyBatch(validKeyBatch.get(), signViewVal, signatureModelVal);
    });

    WaitForAsyncUtils.waitForFxEvents();


    ComboBox<String> signatureSchemeDropdown = robot.lookup("#signatureSchemeDropdown")
      .queryAs(ComboBox.class);
    robot.clickOn(signatureSchemeDropdown);
    robot.clickOn("ISO\\IEC 9796-2 Scheme 1");
    ComboBox<String> hashFunctionDropdown = lookup("#hashFunctionDropdown").queryComboBox();
    robot.clickOn(hashFunctionDropdown);
    robot.clickOn("SHA-256");
    robot.scroll(10, VerticalDirection.UP);
    Platform.runLater(() -> {
      robot.clickOn("#SigBenchmarkButton");
    });

    WaitForAsyncUtils.waitForFxEvents();


    ProgressBar progressBar = robot.lookup("#progressBar").queryAs(ProgressBar.class);
    WaitForAsyncUtils.waitForFxEvents();
    WaitForAsyncUtils.waitFor(1, TimeUnit.SECONDS, () -> progressBar.getProgress() >= 1);


    // Check that the results title label is displayed and correct
    Platform.runLater(() -> {
      Label resultsTitleLabel = robot.lookup("#resultsLabel").queryAs(Label.class);
      assertEquals("Benchmarking Results for Signature Creation (ISO/IEC 9796-2 Scheme 1-SHA-256)", resultsTitleLabel.getText());
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

      robot.clickOn(exportBenchmarkingResultsBtn);
      waitForExportDialogToShow(robot);
      robot.clickOn(robot
        .from(((Stage) robot.window("Export")).getScene().getRoot())
        .lookup(".button")
        .match(hasText("OK"))
        .queryButton());


      Optional<File> benchmarkingResultsFile = MainTestUtility.getFile(
        "Benchmarking Results for Signature Creation (ISO-IEC 9796-2 Scheme 1)_" + keyLengths[i] + "bit", ".csv");
      assertTrue(benchmarkingResultsFile.isPresent(), "Expected export file not found.");
      assertTrue(benchmarkingResultsFile.get().exists(), "Exported file should exist.");

      // Verify that the statistics table is populated
      TableView<?> tableView = robot.lookup("#tableView").queryAs(TableView.class);
      assertFalse(tableView.getItems().isEmpty(), "The table should have data.");


    }


    // Check for the presence of the export buttons and their texts
    Button signatureBatchBtn = robot.lookup("#exportSignatureBatchBtn").queryAs(Button.class);
    Button exportNonRecoverableMessageBatchBtn = robot.lookup("#exportNonRecoverableMessageBatchBtn").queryAs(Button.class);


    // Verify that buttons are visible and then simulate clicks
    assertTrue(signatureBatchBtn.isVisible(), "Export signature batch button should be visible.");
    assertTrue(exportNonRecoverableMessageBatchBtn.isVisible(), "Export non recoverable message batch button should be visible.");


    robot.clickOn(signatureBatchBtn);
    waitForExportDialogToShow(robot);
    robot.clickOn(robot
      .from(((Stage) robot.window("Export")).getScene().getRoot())
      .lookup(".button")
      .match(hasText("OK"))
      .queryButton());
    robot.clickOn(exportNonRecoverableMessageBatchBtn);
    waitForExportDialogToShow(robot);
    robot.clickOn(robot
      .from(((Stage) robot.window("Export")).getScene().getRoot())
      .lookup(".button")
      .match(hasText("OK"))
      .queryButton());


    Optional<File> signatureBatchFile = MainTestUtility.getFile("signatureBatch", ".rsa");
    assertTrue(signatureBatchFile.isPresent(), "Expected exported file not found.");
    assertTrue(signatureBatchFile.get().exists(), "Exported file should exist.");
    Optional<File> nonRecoverableMessageBatchFile = MainTestUtility.
      getFile("nonRecoverableMessageBatch", ".txt");
    assertTrue(nonRecoverableMessageBatchFile.isPresent(), "Expected exported file not found.");
    assertTrue(nonRecoverableMessageBatchFile.get().exists(), "Exported file should exist.");


  }

}
