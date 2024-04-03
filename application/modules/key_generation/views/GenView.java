package uk.msci.project.rsa;

import java.util.*;
import java.util.regex.Pattern;
import javafx.beans.value.ChangeListener;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonBar.ButtonData;
import javafx.scene.control.ButtonType;
import javafx.scene.control.CheckBox;
import javafx.scene.control.Dialog;
import javafx.scene.control.DialogPane;
import javafx.scene.control.Label;
import javafx.scene.control.RadioButton;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.ScrollPane.ScrollBarPolicy;
import javafx.scene.control.TextField;
import javafx.scene.control.Toggle;
import javafx.scene.control.ToggleGroup;
import javafx.scene.effect.GaussianBlur;
import javafx.scene.image.ImageView;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.Modality;
import javafx.stage.Stage;
import javafx.util.Pair;
import org.controlsfx.control.ToggleSwitch;
import uk.msci.project.rsa.HashFunctionSelection;
import uk.msci.project.rsa.KeyConfigurationsDialog;
import uk.msci.project.rsa.KeyGenUtil;


/**
 * The domain object corresponding to GenView FXML file that will serve as a controllers interface
 * into observing and manipulating the graphical layout of the view.
 */
public class GenView {

  /**
   * ImageView that possibly contains a logo or relevant image for the application.
   */
  @FXML
  private ImageView logoImageView;

  /**
   * TextField for the user to enter the desired key sizes, separated by commas.
   */
  @FXML
  private TextField keySizeTextField;

  /**
   * Button that triggers the generation of keys when clicked.
   */
  @FXML
  private Button generateButton;

  /**
   * TextField for the user to enter the desired number of keys.
   */
  @FXML
  private TextField numKeysTextField;

  /**
   * Button that triggers the dynamic generation of corresponding text fields for user to input
   * multiple keys
   */
  @FXML
  private Button numKeysButton;

  /**
   * VBox that contains elements to be shown when key generation is successful.
   */
  @FXML
  private VBox successPopup;

  /**
   * VBox that contains elements to be displayed when key generation fails.
   */
  @FXML
  private VBox failurePopup;

  /**
   * Label to display failure messages.
   */
  @FXML
  private Label failureLabel;

  /**
   * Button to export the generated private key.
   */
  @FXML
  private Button exportPrivateKeyButton;

  /**
   * Button to export the generated public key.
   */
  @FXML
  private Button exportPublicKeyButton;

  /**
   * Button to navigate back to the main menu.
   */
  @FXML
  private Button backToMainMenuButton;

  /**
   * Button that provides help information when clicked.
   */
  @FXML
  private Button helpButton;

  /**
   * Radio button for opting out of cross-parameter benchmarking.
   */
  @FXML
  private RadioButton noCrossParameterRadio;

  /**
   * Radio button for opting in for cross-parameter benchmarking.
   */
  @FXML
  private RadioButton yesCrossParameterRadio;

  /**
   * Label for displaying the number of keys.
   */
  @FXML
  private Label numKeysLabel;

  /**
   * Label for displaying the number of key sizes.
   */
  @FXML
  private Label numKeySizesLabel;

  /**
   * Toggle Switch for enabling or disabling Cross-Parameter Benchmarking Mode.
   */
  @FXML
  private ToggleSwitch crossParameterBenchmarkingModeToggle;

  /**
   * List of pairs, each holding an array of integers and a boolean. This list stores dynamic key
   * data, where each pair consists of an array representing key sizes and a boolean indicating
   * whether a small exponent 'e' is used.
   */
  private List<Pair<int[], Boolean>> dynamicKeyData = new ArrayList<>();

  /**
   * A list storing dynamic key configuration data. Each entry in the list is a pair, where the
   * first element is an array of integers representing key configuration parameters and the second
   * element is a boolean indicating the use of a small 'e' value in the key generation.
   */
  private List<Pair<int[], Boolean>> dynamicKeyConfigurationsData = new ArrayList<>();

  /**
   * List of integers representing dynamically generated key sizes.
   */
  private List<Integer> dynamicKeySizeData = new ArrayList<>();


  /**
   * Integer holding the number of trials for key generation. This is used primarily in benchmarking
   * mode to specify how many times key generation should be performed per key.
   */
  private int numTrials;

  /**
   * Stores the number of key configurations specified by the user for benchmarking.
   */
  private int numKeyConfigs;


  /**
   * Toggle switch for enabling or disabling benchmarking mode.
   */
  @FXML
  private ToggleSwitch benchmarkingModeToggle;

  /**
   * VBox for standard key generation mode. This VBox contains the UI elements relevant to the
   * standard key generation mode, including input fields for key size and the generate keys
   * button.
   */
  @FXML
  private VBox standardModeVBox;

  /**
   * VBox for benchmarking mode. This VBox contains UI elements specific to the benchmarking mode,
   * such as the field for entering the number of keys to be generated.
   */
  @FXML
  private VBox benchmarkingModeVBox;

  /**
   * Toggle group for cross-benchmarking options.
   */
  @FXML
  private ToggleGroup crossBenchMarkingToggleGroup;

  /**
   * Radio button for opting in to generation of a key arbitrary e.
   */
  @FXML
  private RadioButton noSmallEradio;

  /**
   * Radio button for opting in to generation of a key with a small e.
   */
  @FXML
  private RadioButton yesSmallEradio;


  /**
   * Toggle group for small e options.
   */
  private ToggleGroup smallEToggleGroup;

  /**
   * Maps each key configuration group to a list of hash function selections. Each entry in the map
   * associates a group index with a list of {@link HashFunctionSelection} instances, representing
   * hash function choices and their provable security status.
   */
  private Map<Integer, List<HashFunctionSelection>> keyConfigToHashFunctionsMap = new HashMap<>();

  /**
   * Specifies the number of keys per group in a custom cross-parameter benchmarking session. This
   * value is used to determine how many keys are processed together with the same set of hash
   * functions, allowing for batch processing and comparison under similar cryptographic
   * conditions.
   */
  private int keysPerGroup;

  /**
   * Initialises the domain object class. This method is automatically called after the FXML file
   * has been loaded. It sets up the toggle group for cross-benchmarking options.
   */
  public void initialize() {
    crossBenchMarkingToggleGroup = new ToggleGroup();
    noCrossParameterRadio.setToggleGroup(crossBenchMarkingToggleGroup);
    yesCrossParameterRadio.setToggleGroup(crossBenchMarkingToggleGroup);

    smallEToggleGroup = new ToggleGroup();
    noSmallEradio.setToggleGroup(smallEToggleGroup);
    yesSmallEradio.setToggleGroup(smallEToggleGroup);

  }

  /**
   * Registers an observer for when the small e toggle changes value.
   *
   * @param observer The observer to be registered.
   */
  public void addSmallEToggleGroupChangeObserver(ChangeListener<Toggle> observer) {
    smallEToggleGroup.selectedToggleProperty().addListener(observer);
  }


  /**
   * Gets the selected option for whether to use a small public exponent in the generation of kay.
   *
   * @return String representing the selected cross-parameter benchmarking option.
   */
  public String getSmallEToggle() {
    RadioButton selectedButton = (RadioButton) smallEToggleGroup.getSelectedToggle();
    return selectedButton != null ? selectedButton.getText() : "";
  }


  /**
   * Gets the selected option for cross-parameter benchmarking.
   *
   * @return String representing the selected cross-parameter benchmarking option.
   */
  public String getCrossBenchMarkingToggle() {
    RadioButton selectedButton = (RadioButton) crossBenchMarkingToggleGroup.getSelectedToggle();
    return selectedButton != null ? selectedButton.getText() : "";
  }

  /**
   * Registers an observer for when the cross-benchmarking toggle changes value.
   *
   * @param observer The observer to be registered.
   */
  public void addCrossBenchMarkingToggleGroupChangeObserver(ChangeListener<Toggle> observer) {
    crossBenchMarkingToggleGroup.selectedToggleProperty().addListener(observer);
  }

  /**
   * Gets the ImageView that may contain a logo.
   *
   * @return ImageView the ImageView component.
   */
  public ImageView getLogoImageView() {
    return logoImageView;
  }

  /**
   * Sets the logo image view.
   *
   * @param logoImageView The ImageView to set.
   */
  public void setLogoImageView(ImageView logoImageView) {
    this.logoImageView = logoImageView;
  }

  /**
   * Retrieves the key size specified in the TextField.
   *
   * @return String the key size text.
   */
  public String getKeySize() {
    return keySizeTextField.getText();
  }

  /**
   * Retrieves the number of keys specified in the corresponding TextField.
   *
   * @return String the number of keys represented as text.
   */
  public String getNumKeys() {
    return numKeysTextField.getText();
  }

  public void setNumKeys(String text) {
    numKeysTextField.setText(text);
  }

  /**
   * Sets the key size in the TextField.
   *
   * @param keySize A string representing the key size.
   */
  public void setKeySize(String keySize) {
    this.keySizeTextField.setText(keySize);
  }

  /**
   * Sets the failure message label text.
   *
   * @param label The failure message to display.
   */
  public void setFailureLabel(String label) {
    this.failureLabel.setText(label);
  }

  /**
   * Gets the VBox that is shown on successful key generation.
   *
   * @return VBox the success popup component.
   */
  public VBox getSuccessPopup() {
    return successPopup;
  }

  /**
   * Sets the visibility of the success popup.
   *
   * @param visible A boolean to set the popup's visibility.
   */
  public void setSuccessPopupVisible(boolean visible) {
    this.successPopup.setVisible(visible);
    this.successPopup.setManaged(visible);
  }

  /**
   * Sets the visibility of the failure popup.
   *
   * @param visible A boolean to set the popup's visibility.
   */
  public void setFailurePopupVisible(boolean visible) {
    this.failurePopup.setVisible(visible);
  }

  /**
   * Registers an observer for the generate button action event.
   *
   * @param observer The event handler to observe the action.
   */
  void addGenerateButtonObserver(EventHandler<ActionEvent> observer) {
    generateButton.setOnAction(observer);
  }

  /**
   * Registers an observer for the export private key button action event.
   *
   * @param observer The event handler to observe the action.
   */
  void addExportPrivateKeyObserver(EventHandler<ActionEvent> observer) {
    exportPrivateKeyButton.setOnAction(observer);
  }

  /**
   * Registers an observer for the export public key button action event.
   *
   * @param observer The event handler to observe the action.
   */
  void addExportPublicKeyObserver(EventHandler<ActionEvent> observer) {
    exportPublicKeyButton.setOnAction(observer);
  }

  /**
   * Registers an observer for the back to main menu button action event.
   *
   * @param observer The event handler to observe the action.
   */
  void addBackToMainMenuObserver(EventHandler<ActionEvent> observer) {
    backToMainMenuButton.setOnAction(observer);
  }

  /**
   * Registers an observer for the help button action event.
   *
   * @param observer The event handler to observe the action.
   */
  void addHelpObserver(EventHandler<ActionEvent> observer) {
    helpButton.setOnAction(observer);
  }

  /**
   * Registers an observer for the number of keys button click event.
   *
   * @param observer The event handler to observe the action.
   */
  void addNumKeysObserver(EventHandler<ActionEvent> observer) {
    numKeysButton.setOnAction(observer);
  }

  /**
   * Displays a dialog for dynamic field generation based on the number of fields specified. This
   * method allows users to enter multiple key sizes and small e selections.
   *
   * @param numberOfFields The number of key fields to be generated in the dialog.
   * @param primaryStage   The primary stage of the application.
   * @return boolean indicating if the dialog submission was completed successfully.
   */
  boolean showDynamicFieldsDialog(int numberOfFields, Stage primaryStage) {
    Dialog<Void> dialog = new Dialog<>();
    dialog.setTitle("Individual Key Fields");
    dialog.initModality(Modality.APPLICATION_MODAL);
    dialog.initOwner(primaryStage);

    // Create the VBox to hold fields and checkboxes
    VBox content = new VBox(10);

    // Generate the dynamic fields
    for (int i = 0; i < numberOfFields; i++) {
      TextField textField = new TextField();
      textField.setPromptText("Enter multiple bit sizes, separated by commas");
      textField.setPrefWidth(300);
      CheckBox checkBox = new CheckBox("Small e?");
      HBox hbox = new HBox(10, textField, checkBox);
      content.getChildren().add(hbox);
    }
    ScrollPane scrollPane = new ScrollPane(content);
    scrollPane.setVbarPolicy(ScrollBarPolicy.AS_NEEDED);
    scrollPane.setHbarPolicy(ScrollBarPolicy.NEVER); // Disable horizontal scrolling
    scrollPane.setFitToWidth(true);

    ButtonType okButtonType = new ButtonType("Submit", ButtonData.OK_DONE);
    ButtonType cancelButtonType = new ButtonType("Cancel", ButtonData.CANCEL_CLOSE);

    // Set the dialog content and buttons
    DialogPane dialogPane = dialog.getDialogPane();
    dialogPane.setContent(scrollPane);
    dialogPane.getButtonTypes().addAll(okButtonType, cancelButtonType);
    dialogPane.setPrefSize(400, 250);

    final boolean[] isCompleted = {false};

    Button okButton = (Button) dialogPane.lookupButton(okButtonType);
    okButton.addEventFilter(ActionEvent.ACTION, event -> {
      if (isValidInput(content)) {
        isCompleted[0] = true;
        dialog.close();
      } else {
        event.consume(); // Prevent dialog from closing
      }
    });

    primaryStage.getScene().getRoot().setEffect(new GaussianBlur());

    dialog.setOnHidden(e -> primaryStage.getScene().getRoot().setEffect(null));
    dialog.showAndWait();

    return isCompleted[0];
  }


  /**
   * Shows a dialog for dynamic configuration of key parameters, such as key sizes and hash
   * functions. This method is used for setting up the benchmarking mode where each key group can
   * have different key configurations, associated with sets of hash functions.
   *
   * @param numberOfFields The number of configuration fields to generate in the dialog.
   * @param primaryStage   The primary stage of the application.
   * @return boolean indicating if the dialog submission was completed successfully.
   */
  boolean showKeyConfigurationsDialog(int numberOfFields, Stage primaryStage) {
    KeyConfigurationsDialog keyConfigDialog = new KeyConfigurationsDialog(primaryStage,
        dynamicKeyConfigurationsData, keyConfigToHashFunctionsMap, keysPerGroup);
    return keyConfigDialog.showKeyConfigurationsDialog(numberOfFields);
  }

  /**
   * Displays a dialog for dynamic field generation in comparison mode. This dialog allows users to
   * enter single bit sizes for each key.
   *
   * @param numberOfFields The number of key fields to be generated in the dialog.
   * @param primaryStage   The primary stage of the application.
   * @return boolean indicating if the dialog submission was completed successfully.
   */
  boolean showDynamicFieldsDialogComparisonMode(int numberOfFields, Stage primaryStage) {
    Dialog<Void> dialog = new Dialog<>();
    dialog.setTitle("Key Size Fields");
    dialog.initModality(Modality.APPLICATION_MODAL);
    dialog.initOwner(primaryStage);

    // Create the VBox to hold fields and checkboxes
    VBox content = new VBox(10);

    // Generate the dynamic fields
    for (int i = 0; i < numberOfFields; i++) {
      TextField textField = new TextField();
      textField.setPromptText("Enter a Single bit size");
      HBox hbox = new HBox(10, textField);
      content.getChildren().add(hbox);
    }
    ScrollPane scrollPane = new ScrollPane(content);
    scrollPane.setVbarPolicy(ScrollBarPolicy.AS_NEEDED);
    scrollPane.setHbarPolicy(ScrollBarPolicy.NEVER); // Disable horizontal scrolling
    scrollPane.setFitToWidth(true);

    ButtonType okButtonType = new ButtonType("Submit", ButtonData.OK_DONE);
    ButtonType cancelButtonType = new ButtonType("Cancel", ButtonData.CANCEL_CLOSE);

    // Set the dialog content and buttons
    DialogPane dialogPane = dialog.getDialogPane();
    dialogPane.setContent(scrollPane);
    dialogPane.getButtonTypes().addAll(okButtonType, cancelButtonType);
    dialogPane.setPrefSize(275, 250);

    final boolean[] isCompleted = {false};

    Button okButton = (Button) dialogPane.lookupButton(okButtonType);
    okButton.addEventFilter(ActionEvent.ACTION, event -> {
      if (isValidInputComparisonMode(content)) {
        isCompleted[0] = true;
        dialog.close();
      } else {
        event.consume(); // Prevent dialog from closing
        uk.msci.project.rsa.DisplayUtility.showErrorAlert(
            "Each Key Size must be a valid integer between 1024 and 7680. Please try again.");
      }
    });

    primaryStage.getScene().getRoot().setEffect(new GaussianBlur());

    dialog.setOnHidden(e -> primaryStage.getScene().getRoot().setEffect(null));
    dialog.showAndWait();

    return isCompleted[0];
  }

  /**
   * Validates the input provided in the dynamic fields within the given VBox. It checks if the text
   * fields contain valid key size patterns and updates `dynamicKeyData` with the entered key sizes
   * and small e options. If invalid input is detected, the method highlights the respective text
   * field(s) and returns false.
   *
   * @param content The VBox containing dynamically generated text fields and checkboxes.
   * @return boolean indicating whether the input in all text fields is valid.
   */
  private boolean isValidInput(VBox content) {
    dynamicKeyData.clear();
    boolean invalidField = false;
    for (Node node : content.getChildren()) {
      if (node instanceof HBox) {
        HBox hbox = (HBox) node;
        TextField textField = (TextField) hbox.getChildren().get(0);
        CheckBox checkBox = (CheckBox) hbox.getChildren().get(1);

        textField.setStyle("");

        if (!(Pattern.compile("^\\s*\\d+(?:\\s*,\\s*\\d+)+\\s*$").matcher(textField.getText()).matches())) {
          invalidField = true;
          textField.setStyle("-fx-control-inner-background: #FFDDDD;");
        } else {
          String textFieldValue = textField.getText();
          boolean checkBoxValue = checkBox.isSelected();

          int[] numbers = KeyGenUtil.convertStringToIntArray(textFieldValue);
          int sum = Arrays.stream(numbers).sum();

          if (sum < 1024 || sum > 7168) {
            invalidField = true;
            textField.setStyle("-fx-control-inner-background: #FFDDDD;");
          } else {
            dynamicKeyData.add(new Pair<>(numbers, checkBoxValue));
          }
        }
      }
    }
    return !invalidField;
  }



  /**
   * Validates the input provided in the dynamic fields for comparison mode within the given VBox.
   * It checks if the text fields contain valid single bit sizes and updates `dynamicKeySizeData`
   * with the entered key sizes. If invalid input is detected, the respective text field(s) are
   * highlighted and false is returned.
   *
   * @param content The VBox containing dynamically generated text fields.
   * @return boolean indicating whether the input in all text fields is valid.
   */
  private boolean isValidInputComparisonMode(VBox content) {
    dynamicKeySizeData.clear();
    boolean invalidField = false;
    for (Node node : content.getChildren()) {
      if (node instanceof HBox) {
        HBox hbox = (HBox) node;
        TextField textField = (TextField) hbox.getChildren().get(0);
        textField.setStyle("");

        if (!(Pattern.compile("(102[4-9]|[1-6][0-9]{3}|7680)").matcher(textField.getText())
            .matches())) {
          invalidField = true;
          textField.setStyle("-fx-control-inner-background: #FFDDDD;");
        } else {
          String textFieldValue = textField.getText();
          dynamicKeySizeData.add(((Integer.parseInt(textFieldValue) + 7) / 8) * 8);
        }

      }
    }
    return !invalidField;
  }

  /**
   * Displays a dialog for entering the number of trials for key generation. This method allows
   * users to input the number of trials for benchmarking.
   *
   * @param primaryStage The primary stage of the application.
   * @return boolean indicating if the dialog submission was completed successfully.
   */
  boolean showTrialsDialog(Stage primaryStage) {
    Dialog<Void> dialog = new Dialog<>();
    dialog.setTitle("Number of Trials");
    dialog.initModality(Modality.APPLICATION_MODAL);
    dialog.initOwner(primaryStage);

    // Create TextField for user input
    TextField trialsField = new TextField();
    trialsField.setPromptText("Enter number of trials");

    // Create and set the dialog content
    DialogPane dialogPane = dialog.getDialogPane();
    dialogPane.setContent(new VBox(10, trialsField));
    dialogPane.setPrefSize(300, 150);

    // Add OK and Cancel buttons
    ButtonType okButtonType = new ButtonType("OK", ButtonData.OK_DONE);
    ButtonType cancelButtonType = new ButtonType("Cancel", ButtonData.CANCEL_CLOSE);
    dialogPane.getButtonTypes().addAll(okButtonType, cancelButtonType);

    // Event handling
    final boolean[] isCompleted = {false};
    Button okButton = (Button) dialogPane.lookupButton(okButtonType);
    okButton.addEventFilter(ActionEvent.ACTION, event -> {
      try {
        numTrials = Integer.parseInt(trialsField.getText());
        if (!(numTrials > 0)) {
          throw new NumberFormatException();
        }
        isCompleted[0] = true;
      } catch (NumberFormatException e) {
        // Show an error alert if the input is not a valid integer
        uk.msci.project.rsa.DisplayUtility.showErrorAlert(
            "You must provide a valid number of trials. Please try again.");
        event.consume(); // Prevent the dialog from closing
      }
    });

    // Apply a blur effect on the primary stage
    primaryStage.getScene().getRoot().setEffect(new GaussianBlur());
    dialog.setOnHidden(e -> primaryStage.getScene().getRoot().setEffect(null));

    dialog.showAndWait();

    return isCompleted[0];
  }

  /**
   * Displays a dialog for configuring the number of key configurations and the number of keys per
   * group. This dialog allows the user to specify how many different key configurations (i.e., sets
   * of keys with unique properties or parameters) will be used, as well as how many keys are
   * included in each group for batch processing.
   * <p>
   * If the user enters invalid data (e.g., non-integer values, mismatched group sizes), the dialog
   * will display an error message and prompt for correction.
   *
   * @param primaryStage The primary stage of the application, used to set the owner of the dialog.
   * @return boolean indicating whether the user successfully completed the dialog. Returns true if
   * the user entered valid data and confirmed their choices, false if the dialog was cancelled or
   * closed without valid input.
   */
  boolean showNumKeyConfigsDialog(Stage primaryStage) {
    Dialog<Void> dialog = new Dialog<>();
    dialog.setTitle("Number of Key Configurations");
    dialog.initModality(Modality.APPLICATION_MODAL);
    dialog.initOwner(primaryStage);

    // Create TextFields for user input
    TextField keyConfigsField = new TextField();
    keyConfigsField.setPromptText("Enter number of key configurations");
    keyConfigsField.setMaxWidth(250);
    keyConfigsField.setPrefWidth(250);

    TextField keysPerGroupField = new TextField();
    keysPerGroupField.setPromptText("Enter number of keys per group");
    keysPerGroupField.setMaxWidth(200);
    keysPerGroupField.setPrefWidth(200);

    Label infoTooltip = new Label(
        "Configure Batch Benchmarking per Key Sizes:\n\n" +
            "- Number of Key Configurations: Define the uniform number of key configurations to benchmark per key size.\n"
            +
            "- Keys per Group: Specify the number of keys within each group of configurations.\n\n"
            +
            "Example Configuration:\n" +
            "   Total Key Configurations: 10\n" +
            "   Keys Per Group: 5\n" +
            "   In this setup:\n" +
            "   - The first group comprises the initial 5 key configurations, each using a its own set of hash functions.\n"
            +
            "   - The subsequent group includes the remaining 5 key configurations, again with a its own set of hash functions.\n"
            +
            "   - These groups are processed one after the other."
    );

    infoTooltip.setWrapText(true);

    // Group keysPerGroupField and infoLabel together
    HBox keysPerGroupContainer = new HBox(5, keysPerGroupField);
    keysPerGroupContainer.setAlignment(Pos.CENTER_LEFT);

    // Create and set the dialog content
    DialogPane dialogPane = dialog.getDialogPane();
    VBox content = new VBox(10, keyConfigsField, keysPerGroupContainer, infoTooltip);
    dialogPane.setContent(content);
    dialogPane.setPrefSize(350, 470);

    // Add OK and Cancel buttons
    ButtonType okButtonType = new ButtonType("OK", ButtonData.OK_DONE);
    ButtonType cancelButtonType = new ButtonType("Cancel", ButtonData.CANCEL_CLOSE);
    dialogPane.getButtonTypes().addAll(okButtonType, cancelButtonType);

    // Event handling
    final boolean[] isCompleted = {false};
    Button okButton = (Button) dialogPane.lookupButton(okButtonType);
    okButton.addEventFilter(ActionEvent.ACTION, event -> {
      try {
        int numKeyConfigs = Integer.parseInt(keyConfigsField.getText());
        int keysPerGroup = Integer.parseInt(keysPerGroupField.getText());

        if (numKeyConfigs % keysPerGroup != 0) {
          throw new IllegalArgumentException(
              "The number of keys per group must evenly divide the total number of key configurations.");
        }

        this.numKeyConfigs = numKeyConfigs;
        this.keysPerGroup = keysPerGroup;
        isCompleted[0] = true;
      } catch (NumberFormatException e) {
        uk.msci.project.rsa.DisplayUtility.showErrorAlert(
            "The number of keys per group must evenly divide the total number of key configurations.");
        event.consume();
      } catch (IllegalArgumentException e) {
        uk.msci.project.rsa.DisplayUtility.showErrorAlert(e.getMessage());
        event.consume();
      }
    });

    // Apply a blur effect on the primary stage
    primaryStage.getScene().getRoot().setEffect(new GaussianBlur());
    dialog.setOnHidden(e -> primaryStage.getScene().getRoot().setEffect(null));

    dialog.showAndWait();

    return isCompleted[0];
  }

  /**
   * Retrieves a list of key parameters (sizes and small e options) specified by the user.
   *
   * @return List<Pair < int [ ], Boolean>> containing the key parameters.
   */
  public List<Pair<int[], Boolean>> getDynamicKeyData() {
    return dynamicKeyData;
  }

  /**
   * Retrieves the dynamic key configurations data specified by the user.
   *
   * @return A list of pairs, each containing key configuration parameters and a boolean indicating
   * the use of a small 'e' value.
   */
  public List<Pair<int[], Boolean>> getDynamicKeyConfigurationsData() {
    return dynamicKeyConfigurationsData;
  }

  /**
   * Retrieves a list of key sizes specified by the user in comparison mode.
   *
   * @return List<Integer> containing the specified key sizes.
   */
  public List<Integer> getDynamicKeySizeData() {
    return dynamicKeySizeData;
  }

  /**
   * Retrieves the number of trials specified for key generation.
   *
   * @return int representing the number of trials.
   */
  public int getNumTrials() {
    return numTrials;
  }

  /**
   * Registers an observer for when the benchmarking mode toggle switch value changes.
   *
   * @param observer The change listener to be registered.
   */
  public void addBenchmarkingModeToggleObserver(ChangeListener<Boolean> observer) {
    benchmarkingModeToggle.selectedProperty().addListener(observer);
  }

  /**
   * Sets the visibility of the standardModeVBox.
   *
   * @param visible A boolean indicating whether the standardModeVBox should be visible.
   */
  public void setStandardModeVBoxVisibility(boolean visible) {
    standardModeVBox.setVisible(visible);
    standardModeVBox.setManaged(visible);
  }

  /**
   * Sets the visibility of the benchmarkingModeVBox.
   *
   * @param visible A boolean indicating whether the benchmarkingModeVBox should be visible.
   */
  public void setBenchmarkingModeVBoxVisibility(boolean visible) {
    benchmarkingModeVBox.setVisible(visible);
    benchmarkingModeVBox.setManaged(visible);
  }

  /**
   * Sets the visibility of the numKeysButton.
   *
   * @param visible A boolean indicating whether the numKeysButton should be visible.
   */
  public void setNumKeysButtonVisibility(boolean visible) {
    numKeysButton.setVisible(visible);
    numKeysButton.setManaged(visible);
  }

  /**
   * Sets the visibility of the generateButton.
   *
   * @param visible A boolean indicating whether the generateButton should be visible.
   */
  public void setGenerateButtonVisibility(boolean visible) {
    generateButton.setVisible(visible);
    generateButton.setManaged(visible);
  }

  /**
   * Sets the visibility of the label displaying the number of key sizes.
   *
   * @param visible A boolean indicating whether the label should be visible.
   */
  public void setNumKeySizesLabelVisibility(boolean visible) {
    this.numKeySizesLabel.setManaged(visible);
    this.numKeySizesLabel.setVisible(visible);
  }

  /**
   * Checks to see if the comparison mode key sizes label is currently being displayed.
   *
   * @return A boolean indicating whether the label is visible.
   */
  public boolean getNumKeySizesVisibility() {
    return numKeySizesLabel.isVisible();
  }

  /**
   * Sets the visibility of the label displaying the number of keys.
   *
   * @param visible A boolean indicating whether the label should be visible.
   */
  public void setNumKeysLabelVisibility(boolean visible) {
    this.numKeysLabel.setManaged(visible);
    this.numKeysLabel.setVisible(visible);
  }

  /**
   * Adds an observer for the Cross-Parameter toggle switch.
   *
   * @param observer the observer to be notified when the toggle state changes.
   */
  public void addCrossParameterToggleObserver(ChangeListener<Boolean> observer) {
    crossParameterBenchmarkingModeToggle.selectedProperty().addListener(observer);
  }

  /**
   * Sets the selected state of the Cross-Parameter toggle switch.
   *
   * @param isSelected true to select the toggle switch, false otherwise.
   */
  public void setSelectedCrossParameterToggleObserver(boolean isSelected) {
    crossParameterBenchmarkingModeToggle.setSelected(isSelected);
  }

  /**
   * Adds an observer for changes in the provable scheme selection.
   *
   * @param observer the observer to be notified when the scheme selection changes.
   */
  public void addCrossParameterRadioChangeObserver(ChangeListener<Toggle> observer) {
    crossBenchMarkingToggleGroup.selectedToggleProperty().addListener(observer);
  }

  /**
   * Retrieves the number of key configurations specified by the user in the initialisation of
   * custom cross parameter benchmarking session.
   *
   * @return number represent the current number of key configurations.
   */
  public int getNumKeyConfigs() {
    return numKeyConfigs;
  }

  /**
   * Retrieves the mapping of key configuration groups to their respective hash functions. This
   * method is used to obtain the configured hash functions for each group of keys in the
   * cross-parameter benchmarking mode.
   *
   * @return A map where each key is a group index and the value is a list of hash function
   * selections.
   */
  public Map<Integer, List<HashFunctionSelection>> getKeyConfigToHashFunctionsMap() {
    return keyConfigToHashFunctionsMap;
  }

  /**
   * Gets the number of keys per group in the cross-parameter benchmarking mode. This value is
   * essential for organising the key groups and associating them with their respective hash
   * function selections.
   *
   * @return int representing the number of keys per group.
   */
  public int getKeysPerGroup() {
    return keysPerGroup;
  }
}
