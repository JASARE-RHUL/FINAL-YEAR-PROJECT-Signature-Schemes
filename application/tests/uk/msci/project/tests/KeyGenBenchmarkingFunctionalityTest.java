package uk.msci.project.tests;

import com.jfoenix.controls.JFXTabPane;
import javafx.application.Platform;
import javafx.geometry.VerticalDirection;
import javafx.scene.Node;
import javafx.scene.control.*;
import javafx.scene.image.ImageView;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;
import javafx.util.Pair;
import org.controlsfx.control.ToggleSwitch;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.testfx.api.FxRobot;
import org.testfx.framework.junit5.ApplicationExtension;
import org.testfx.framework.junit5.ApplicationTest;
import org.testfx.framework.junit5.Start;
import org.testfx.matcher.control.LabeledMatchers;
import org.testfx.util.WaitForAsyncUtils;
import uk.msci.project.rsa.GenRSA;
import uk.msci.project.rsa.MainController;

import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.testfx.api.FxAssert.verifyThat;
import static org.testfx.util.NodeQueryUtils.hasText;
import static uk.msci.project.tests.MainTestUtility.waitForExportDialogToShow;

/**
 * Tests the key generation functionality of the Signature Scheme benchmarking application. This includes
 * verifying the presence and correct behavior of UI components related to key generation benchmarking, as well
 * as the validation and handling of user input and the successful export of generated keys.
 */
public class KeyGenBenchmarkingFunctionalityTest extends ApplicationTest {
  private FxRobot robot;

  private MainController mainController;

  /**
   * Initialises the test fixture with the main stage.
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
   */
  @BeforeEach
  public void setup() {
    robot = new FxRobot();
    robot.clickOn("#generateKeysButton");
    WaitForAsyncUtils.waitForFxEvents();
  }


  /**
   * Checks if key components necessary for the application, like toggles and buttons, are present.
   */
  @Test
  void shouldContainKeyComponents() {
    WaitForAsyncUtils.waitForFxEvents();
    ToggleSwitch benchmarkingModeToggle = (ToggleSwitch) robot.lookup("#benchmarkingModeToggle").query();
    assertNotNull(benchmarkingModeToggle, "The component should exist.");
    ToggleSwitch crossParameterBenchmarkingModeToggle = (ToggleSwitch) robot.lookup("#crossParameterBenchmarkingModeToggle").query();
    assertNotNull(crossParameterBenchmarkingModeToggle, "The component should exist.");
    TextField numKeysTextField = (TextField) robot.lookup("#numKeysTextField").query();
    assertNotNull(numKeysTextField, "The component should exist.");
    Button numKeysButton = (Button) robot.lookup("#numKeysButton").query();
    assertNotNull(numKeysButton, "The component should exist.");
  }

  /**
   * Validates that the number of keys input field rejects invalid input and shows an appropriate error
   * message.
   */
  @Test
  void shouldValidateNumKeysInput() {
    WaitForAsyncUtils.waitForFxEvents();
    TextField keySizeTextField = robot.lookup("#keySizeTextField").queryAs(TextField.class);
    // Input an invalid value
    robot.clickOn(keySizeTextField).write("invalid input");
    robot.clickOn("#numKeysButton");
    // Assert that the failure popup is visible
    assertNotNull((Node) robot.lookup(button -> button instanceof Button &&
        ((Button) button).getText().equals(ButtonType.OK.getText())).tryQuery().orElseThrow(
        () -> new AssertionError("Button with text '" + ButtonType.OK.getText() + "' not found.")
      ),
      "Failure popup box ok button should exist.");
  }


  /**
   * Verifies that the dialog for entering key fields appears correctly upon valid input in the number of keys field.
   * This sets the stage for further interaction with key field inputs.
   */
  @Test
  void shouldDisplayKeyFieldsDialogOnValidInput() {
    WaitForAsyncUtils.waitForFxEvents();
    TextField keySizeTextField = robot.lookup("#numKeysTextField").queryAs(TextField.class);

    // Input a valid value
    robot.clickOn(keySizeTextField).write("2");
    robot.clickOn("#numKeysButton");

    // Wait for the dialog to appear and ensure it's displayed
    WaitForAsyncUtils.waitForFxEvents();
    robot.lookup(".dialog-pane").tryQuery().isPresent();

    // Check for the title of the dialog window
    Stage dialogStage = (Stage) robot.window("Individual Key Fields");
    assertNotNull(dialogStage);
    assertTrue(dialogStage.isShowing());
    assertEquals("Individual Key Fields", dialogStage.getTitle());

    // Check the number of TextField and CheckBox pairs
    // Use robot.from() to scope the search to the dialog window only
    Set<Node> fields = robot.from(dialogStage.getScene().getRoot()).lookup(".text-field").queryAll();
    Set<Node> checkBoxes = robot.from(dialogStage.getScene().getRoot()).lookup(".check-box").queryAll();

    // Assert the expected number of fields and checkboxes
    assertEquals(2, fields.size(), "Expected number of text fields does not match.");
    assertEquals(2, checkBoxes.size(), "Expected number of check boxes does not match.");

  }

  /**
   * Tests error handling for various invalid inputs in the key fields dialog.
   * Ensures that user input in key configuration fields is correctly validated.
   */
  @Test
  void shouldValidateKeyFieldsDialogTextFields() {
    WaitForAsyncUtils.waitForFxEvents();
    TextField keySizeTextField = robot.lookup("#numKeysTextField").queryAs(TextField.class);

    // Input a valid value
    robot.clickOn(keySizeTextField).write("2");
    robot.clickOn("#numKeysButton");

    // Wait for the dialog to appear and ensure it's displayed
    WaitForAsyncUtils.waitForFxEvents();
    robot.lookup(".dialog-pane").tryQuery().isPresent();
    WaitForAsyncUtils.waitForFxEvents();

    Stage dialogStage = (Stage) robot.window("Individual Key Fields");


    Button okButton = robot
      .from(dialogStage.getScene().getRoot())
      .lookup(".button")
      .match(hasText("Submit"))
      .queryButton();
    /**
     * Tests  error handling when aLL text fields are empty.
     */
    robot.clickOn(okButton);

    // Wait for potential UI updates
    WaitForAsyncUtils.waitForFxEvents();

    // Check the text fields for the red background
    String redErrorFieldColour = "-fx-control-inner-background: #FFDDDD;";
    Set<TextField> textFields = robot.from(dialogStage.getScene().getRoot()).lookup(".text-field").queryAllAs(TextField.class);
    for (TextField textField : textFields) {
      String style = textField.getStyle();
      assertEquals(redErrorFieldColour, style);
    }
    Iterator<TextField> textFieldIterator = textFields.iterator();

    TextField firstTextField = textFieldIterator.next();

    /**
     * Tests  error handling when only the second text field is empty.
     */
    robot.clickOn(firstTextField).write("512,512");
    robot.clickOn(okButton);
    TextField secondTextField = textFieldIterator.next();
    assertEquals(redErrorFieldColour, secondTextField.getStyle());


    /**
     * Tests error handling when less than the required amount of prime factors is inputted for a key configuration text field.

     */
    robot.clickOn(secondTextField).write("1024");
    robot.clickOn(okButton);
    assertEquals(redErrorFieldColour, secondTextField.getStyle());
    secondTextField.clear();


    /**
     * Tests error handling when special characters are inputted for a key configuration text field
     */
    robot.clickOn(secondTextField).write("!@#$%^&*()");
    robot.clickOn(okButton);
    assertEquals(redErrorFieldColour, secondTextField.getStyle());
    secondTextField.clear();

    /**
     * Tests error handling when an excessively long numeric input is provided for a key configuration text field
     */
    robot.clickOn(secondTextField).write("11111111111111111111111111111111111111");
    robot.clickOn(okButton);
    assertEquals(redErrorFieldColour, secondTextField.getStyle());
    secondTextField.clear();

    /**
     * Tests error handling when an alphanumeric input is provided for a key configuration text field
     */
    robot.clickOn(secondTextField).write("abc123");
    robot.clickOn(okButton);
    assertEquals(redErrorFieldColour, secondTextField.getStyle());

  }


  private static Stream<Arguments> validKeyConfigurationPairs() {
    return Stream.of(
      Arguments.of(new Pair<>("512,512", true), new Pair<>("1024,1024", true)),
      Arguments.of(new Pair<>("512,512", true), new Pair<>("1024,1024", false)),
      Arguments.of(new Pair<>("512,512", false), new Pair<>("1024,1024", true)),
      Arguments.of(new Pair<>("512,512", false), new Pair<>("1024,1024", false)),
      Arguments.of(new Pair<>("1024,1024", true), new Pair<>("1024,1024", true)),
      Arguments.of(new Pair<>("1024,1024", true), new Pair<>("1024,1024", false)),
      Arguments.of(new Pair<>("1024,1024", false), new Pair<>("1024,1024", true)),
      Arguments.of(new Pair<>("1024,1024", false), new Pair<>("1024,1024", false))
    );
  }

  /**
   * Ensures that the dialog for specifying the number of trials is correctly displayed for valid key configurations.
   *
   * @param keyConfig1 The first key configuration.
   * @param keyConfig2 The second key configuration.
   */
  @ParameterizedTest
  @MethodSource("validKeyConfigurationPairs")
  void shouldDisplayNumTrialsDialogOnValidKeys(Pair<String, Boolean> keyConfig1, Pair<String, Boolean> keyConfig2) {
    WaitForAsyncUtils.waitForFxEvents();
    TextField keySizeTextField = robot.lookup("#numKeysTextField").queryAs(TextField.class);

    // Input a valid value
    robot.clickOn(keySizeTextField).write("2");
    robot.clickOn("#numKeysButton");

    // Wait for the dialog to appear and ensure it's displayed
    WaitForAsyncUtils.waitForFxEvents();
    robot.lookup(".dialog-pane").tryQuery().isPresent();
    WaitForAsyncUtils.waitForFxEvents();

    Stage dialogStage = (Stage) robot.window("Individual Key Fields");


    Button okButton = robot
      .from(dialogStage.getScene().getRoot())
      .lookup(".button")
      .match(hasText("Submit"))
      .queryButton();


    // Wait for potential UI updates
    WaitForAsyncUtils.waitForFxEvents();

    Set<TextField> textFieldsSet = robot.from(dialogStage.getScene().getRoot()).lookup(".text-field").queryAllAs(TextField.class);
    Set<Node> checkBoxesSet = robot.from(dialogStage.getScene().getRoot()).lookup(".check-box").queryAll();

    // Convert Sets to Lists for easier access by index
    List<TextField> textFields = new ArrayList<>(textFieldsSet);
    List<CheckBox> checkBoxes = checkBoxesSet.stream().map(node -> (CheckBox) node).collect(Collectors.toList());


    // Write the key configurations and select checkboxes as per the provided pairs
    if (!textFields.isEmpty() && checkBoxes.size() >= 2) {

      textFields.get(0).setText(keyConfig1.getKey());
      checkBoxes.get(0).setSelected(keyConfig1.getValue());

      textFields.get(1).setText(keyConfig2.getKey());
      checkBoxes.get(1).setSelected(keyConfig2.getValue());
    }

    robot.clickOn(okButton);

    // Check for the title of the dialog window
    dialogStage = (Stage) robot.window("Number of Trials");
    assertNotNull(dialogStage);
    assertTrue(dialogStage.isShowing());
    assertEquals("Number of Trials", dialogStage.getTitle());

  }

  /**
   * Validates error handling for various invalid inputs in the number of trials dialog.
   * Ensures that the user's input for the number of trials is correctly validated.
   */
  @Test
  void shouldValidateNumTrialsDialogTextField() {
    WaitForAsyncUtils.waitForFxEvents();
    TextField keySizeTextField = robot.lookup("#numKeysTextField").queryAs(TextField.class);

    // Input a valid value
    robot.clickOn(keySizeTextField).write("2");
    robot.clickOn("#numKeysButton");

    // Wait for the dialog to appear and ensure it's displayed
    WaitForAsyncUtils.waitForFxEvents();
    robot.lookup(".dialog-pane").tryQuery().isPresent();
    WaitForAsyncUtils.waitForFxEvents();

    Stage dialogStage = (Stage) robot.window("Individual Key Fields");


    Button okButton = robot
      .from(dialogStage.getScene().getRoot())
      .lookup(".button")
      .match(hasText("Submit"))
      .queryButton();


    // Wait for potential UI updates
    WaitForAsyncUtils.waitForFxEvents();

    Set<TextField> textFields = robot.from(dialogStage.getScene().getRoot()).lookup(".text-field").queryAllAs(TextField.class);

    Iterator<TextField> textFieldIterator = textFields.iterator();


    TextField firstTextField = textFieldIterator.next();
    TextField secondTextField = textFieldIterator.next();


    robot.clickOn(firstTextField).write("512,512");
    robot.clickOn(secondTextField).write("1024,1024");

    robot.clickOn(okButton);

    dialogStage = (Stage) robot.window("Number of Trials");
    // Find the trials text field within the "Number of Trials" dialog
    TextField trialsField = robot
      .from(dialogStage.getScene().getRoot())
      .lookup(".text-field")
      .queryAs(TextField.class);

    okButton = robot
      .from(dialogStage.getScene().getRoot())
      .lookup(".button")
      .match(hasText("OK"))
      .queryButton();


    boolean errorDialogShown;

    /**
     * Tests  error handling when the trials field is empty.
     */
    robot.clickOn(okButton);
    errorDialogShown = robot.lookup(".alert").tryQuery().isPresent();
    assertTrue(errorDialogShown, "The error dialog should be shown.");
    Button errorButton = robot
      .from(((Stage) robot.window("Error")).getScene().getRoot())
      .lookup(".button")
      .match(hasText("OK"))
      .queryButton();
    robot.clickOn(errorButton);
    trialsField.clear();


    /**
     * Tests error handling when the trials field contains a special character
     */
    robot.clickOn(trialsField).write("512,512");
    robot.clickOn(okButton);
    errorDialogShown = robot.lookup(".alert").tryQuery().isPresent();
    assertTrue(errorDialogShown, "The error dialog should be shown.");
    errorButton = robot
      .from(((Stage) robot.window("Error")).getScene().getRoot())
      .lookup(".button")
      .match(hasText("OK"))
      .queryButton();
    robot.clickOn(errorButton);
    trialsField.clear();


    /**
     * Tests error handling when the trials field contains a decimal number
     */
    robot.clickOn(trialsField).write("7.6");
    robot.clickOn(okButton);
    errorDialogShown = robot.lookup(".alert").tryQuery().isPresent();
    assertTrue(errorDialogShown, "The error dialog should be shown.");
    errorButton = robot
      .from(((Stage) robot.window("Error")).getScene().getRoot())
      .lookup(".button")
      .match(hasText("OK"))
      .queryButton();
    robot.clickOn(errorButton);
    trialsField.clear();


    /**
     * Tests error handling when the trials field contains a sequence of special characters
     */
    robot.clickOn(trialsField).write("!@#$%^&*()");
    robot.clickOn(okButton);
    errorDialogShown = robot.lookup(".alert").tryQuery().isPresent();
    assertTrue(errorDialogShown, "The error dialog should be shown.");
    errorButton = robot
      .from(((Stage) robot.window("Error")).getScene().getRoot())
      .lookup(".button")
      .match(hasText("OK"))
      .queryButton();
    robot.clickOn(errorButton);
    trialsField.clear();

    /**
     * Tests error handling when the trials field contains a negative number
     */
    robot.clickOn(trialsField).write("-5");
    robot.clickOn(okButton);
    errorDialogShown = robot.lookup(".alert").tryQuery().isPresent();
    assertTrue(errorDialogShown, "The error dialog should be shown.");
    errorButton = robot
      .from(((Stage) robot.window("Error")).getScene().getRoot())
      .lookup(".button")
      .match(hasText("OK"))
      .queryButton();
    robot.clickOn(errorButton);
    trialsField.clear();

    /**
     * Tests error handling when the trials field contains the number 0
     */
    robot.clickOn(trialsField).write("0");
    robot.clickOn(okButton);
    errorDialogShown = robot.lookup(".alert").tryQuery().isPresent();
    assertTrue(errorDialogShown, "The error dialog should be shown.");
    errorButton = robot
      .from(((Stage) robot.window("Error")).getScene().getRoot())
      .lookup(".button")
      .match(hasText("OK"))
      .queryButton();
    robot.clickOn(errorButton);
    trialsField.clear();

    /**
     * Tests error handling when the trials field contains alphanumeric input
     */
    robot.clickOn(trialsField).write("adewfrgtrvbc125663");
    robot.clickOn(okButton);
    errorDialogShown = robot.lookup(".alert").tryQuery().isPresent();
    assertTrue(errorDialogShown, "The error dialog should be shown.");
    errorButton = robot
      .from(((Stage) robot.window("Error")).getScene().getRoot())
      .lookup(".button")
      .match(hasText("OK"))
      .queryButton();
    robot.clickOn(errorButton);


  }




  /**
   * Tests the final stage of the key generation functionality where results should be correctly displayed
   * and the corresponding files are expected to be exported for valid numbers of trials.
   * This test verifies the culmination of all previous stages in the key generation workflow.
   *
   * @throws IOException If an I/O error occurs.
   * @throws TimeoutException If the test times out.
   */
  @Test
  void shouldDisplayResultsOnValidNumTrials() throws IOException, TimeoutException {
    WaitForAsyncUtils.waitForFxEvents();
    TextField keySizeTextField = robot.lookup("#numKeysTextField").queryAs(TextField.class);
    int totalKeys = 2;
    int[] keyLengths = new int[]{1024, 2048};

    // Input a valid value
    robot.clickOn(keySizeTextField).write(String.valueOf(totalKeys));
    robot.clickOn("#numKeysButton");

    // Wait for the dialog to appear and ensure it's displayed
    WaitForAsyncUtils.waitForFxEvents();
    robot.lookup(".dialog-pane").tryQuery().isPresent();
    WaitForAsyncUtils.waitForFxEvents();

    Stage dialogStage = (Stage) robot.window("Individual Key Fields");


    Button okButton = robot
      .from(dialogStage.getScene().getRoot())
      .lookup(".button")
      .match(hasText("Submit"))
      .queryButton();


    // Wait for potential UI updates
    WaitForAsyncUtils.waitForFxEvents();
    Set<TextField> textFieldsSet = robot.from(dialogStage.getScene().getRoot()).lookup(".text-field").queryAllAs(TextField.class);
    Set<Node> checkBoxesSet = robot.from(dialogStage.getScene().getRoot()).lookup(".check-box").queryAll();

    // Convert Sets to Lists for easier access by index
    List<TextField> textFields = new ArrayList<>(textFieldsSet);
    List<CheckBox> checkBoxes = checkBoxesSet.stream().map(node -> (CheckBox) node).collect(Collectors.toList());


    // Write the key configurations and select checkboxes as per the provided pairs
    if (!textFields.isEmpty() && checkBoxes.size() >= totalKeys) {

      textFields.get(0).setText("512,512");
      checkBoxes.get(0).setSelected(true);

      textFields.get(1).setText("1024,1024");
      checkBoxes.get(1).setSelected(false);
    }


    robot.clickOn(okButton);

    dialogStage = (Stage) robot.window("Number of Trials");
    TextField trialsField = robot
      .from(dialogStage.getScene().getRoot())
      .lookup(".text-field")
      .queryAs(TextField.class);

    okButton = robot
      .from(dialogStage.getScene().getRoot())
      .lookup(".button")
      .match(hasText("OK"))
      .queryButton();
    robot.clickOn(trialsField).write("2");

    robot.clickOn(okButton);
    WaitForAsyncUtils.waitForFxEvents();


    ProgressBar progressBar = robot.lookup("#progressBar").queryAs(ProgressBar.class);
    WaitForAsyncUtils.waitForFxEvents();
    WaitForAsyncUtils.waitFor(1, TimeUnit.SECONDS, () -> progressBar.getProgress() >= 1);


    // Check that the results title label is displayed and correct
    Platform.runLater(() -> {
      Label resultsTitleLabel = robot.lookup("#resultsLabel").queryAs(Label.class);
      assertEquals("Benchmarking Results for Key Generation", resultsTitleLabel.getText());
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
        "Benchmarking Results for Key Generation" + "_" + keyLengths[i] + "bit", ".csv");
      assertTrue(benchmarkingResultsFile.isPresent(), "Expected exported file not found.");
      assertTrue(benchmarkingResultsFile.get().exists(), "Exported file should exist.");

      // Verify that the statistics table is populated
      TableView<?> tableView = robot.lookup("#tableView").queryAs(TableView.class);
      assertFalse(tableView.getItems().isEmpty(), "The table should have data.");


    }


    // Check for the presence of the export buttons and their texts
    Button exportPrivateKeyBatchBtn = robot.lookup("#exportPrivateKeyBatchBtn").queryAs(Button.class);
    Button exportPublicKeyBatchBtn = robot.lookup("#exportPublicKeyBatchBtn").queryAs(Button.class);

    // Verify that buttons are visible and then simulate clicks
    assertTrue(exportPrivateKeyBatchBtn.isVisible(), "Export private Key batch button should be visible.");
    assertTrue(exportPublicKeyBatchBtn.isVisible(), "Export public Key batch button should be visible.");


    robot.clickOn(exportPrivateKeyBatchBtn);
    waitForExportDialogToShow(robot);
    robot.clickOn(robot
      .from(((Stage) robot.window("Export")).getScene().getRoot())
      .lookup(".button")
      .match(hasText("OK"))
      .queryButton());
    robot.clickOn(exportPublicKeyBatchBtn);
    waitForExportDialogToShow(robot);
    robot.clickOn(robot
      .from(((Stage) robot.window("Export")).getScene().getRoot())
      .lookup(".button")
      .match(hasText("OK"))
      .queryButton());

    //logic to verify that the keys were actually exported by checking for existence of key files
    //if there are multiple key files then the files are exported with an increasing number suffix
    // getFile retrieves the most recently exported file i.e., the highest number suffix


    Optional<File> privateKeyBatchFile = MainTestUtility.getFile("batchKey", ".rsa");
    assertTrue(privateKeyBatchFile.isPresent(), "Expected exported file not found.");
    assertTrue(privateKeyBatchFile.get().exists(), "Exported file should exist.");

    Optional<File> publicKeyBatchFile = MainTestUtility.getFile("batchPublicKey", ".rsa");
    assertTrue(publicKeyBatchFile.isPresent(), "Expected exported file not found.");
    assertTrue(publicKeyBatchFile.get().exists(), "Exported file should exist.");


  }

}
