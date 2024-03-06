package uk.msci.project.rsa;


import java.util.HashMap;
import java.util.Map;
import javafx.beans.value.ChangeListener;
import javafx.collections.FXCollections;
import javafx.collections.ListChangeListener;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.scene.Node;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.RadioButton;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.control.Toggle;
import javafx.scene.control.ToggleGroup;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.util.StringConverter;
import org.controlsfx.control.CheckComboBox;
import org.controlsfx.control.ToggleSwitch;

/**
 * This class serves as the abstract base class for all views related to the signature processes
 * (generation and verification). The class provides a structured layout for the signature-related
 * views by defining common UI components and behavior that are shared across the different
 * signature views.
 * <p>
 * Te common components include text input, key management, signature scheme and hash function
 * selection, as well as benchmarking-related UI elements. It ensures consistency and reusability of
 * UI components and behavior across different signature views, streamlining the implementation of
 * specific views for signature creation or verification.
 */
public abstract class SignatureBaseView implements SignatureViewInterface {

  @FXML
  /**
   * Text Area for text to be signed.
   */
  private TextArea textInput;

  /**
   * The root pane of the signature view scene.
   */
  @FXML
  private BorderPane root;

  /**
   * Horizontal Box containing the text input components.
   */
  @FXML
  private HBox textInputHBox;


  /**
   * Label displaying the name of the imported text file.
   */
  @FXML
  private Label textFileNameLabel;

  /**
   * ImageView displaying a checkmark indicating successful text file import.
   */
  @FXML
  private ImageView textFileCheckmarkImage;

  /**
   * Button for importing text to be signed.
   */
  @FXML
  private Button importTextButton;
  /**
   * TextField to display the selected private key file or to prompt for key import.
   */
  @FXML
  private TextField keyField;

  /**
   * ImageView to display a checkmark indicating the successful import of a private key.
   */
  @FXML
  private ImageView checkmarkImage;

  /**
   * Button to initiate the import of a private key file.
   */
  @FXML
  private Button importKeyButton;

  /**
   * ComboBox to allow the selection of a signature scheme from predefined options.
   */
  @FXML
  private ComboBox<String> signatureSchemeDropdown;

  /**
   * ComboBox to allow the selection of a hash function from predefined options.
   */
  @FXML
  private ComboBox<String> hashFunctionDropdown;

  /**
   * Button to trigger the creation of a digital signature based on the provided text and selected
   * key.
   */
  @FXML
  private Button createSignatureButton;

  /**
   * Button to navigate back to the main menu of the application.
   */
  @FXML
  private Button backToMainMenuButton;

  /**
   * Button to provide help or additional information to the user.
   */
  @FXML
  private Button helpButton;

  /**
   * StackPane to display notifications and results to the user, such as the success or failure of
   * operations.
   */
  @FXML
  private StackPane notificationPane;


  /**
   * Button to close the notification pane.
   */
  @FXML
  private Button closeNotificationButton;

  /**
   * Toggle switch for enabling or disabling benchmarking mode.
   */
  @FXML
  private ToggleSwitch benchmarkingModeToggle;

  /**
   * Label displaying the number of messages for benchmarking.
   */
  @FXML
  private Label numMessageLabel;

  /**
   * TextField for entering the number of messages for benchmarking.
   */
  @FXML
  private TextField numMessageField;

  /**
   * HBox containing components for entering message batch details.
   */
  @FXML
  private HBox messageBatchHBox;

  /**
   * Label displaying text related to message batch.
   */
  @FXML
  private Label messageBatchText;

  /**
   * TextField for entering details of the message batch.
   */
  @FXML
  private TextField messageBatchField;

  /**
   * ImageView displaying a checkmark indicating successful message batch import.
   */
  @FXML
  private ImageView checkmarkImageMessageBatch;

  /**
   * Button for importing text batch.
   */
  @FXML
  private Button importTextBatchBtn;

  /**
   * Button for canceling text batch import.
   */
  @FXML
  private Button cancelImportTextBatchButton;

  /**
   * Button for canceling text batch import.
   */
  @FXML
  private Button cancelImportTextButton;

  /**
   * Button for importing key batch.
   */
  @FXML
  private Button importKeyBatchButton;

  /**
   * Button for canceling key batch import.
   */
  @FXML
  private Button cancelImportKeyButton;

  /**
   * Button for canceling key import (standard mode).
   */
  @FXML
  private Button cancelImportSingleKeyButton;

  /**
   * Toggle group for selecting the parameter type for signature schemes.
   */
  @FXML
  private ToggleGroup parameterChoiceToggleGroup;

  /**
   * Radio button for selecting standard parameters.
   */
  @FXML
  private RadioButton standardParametersRadio;

  /**
   * Radio button for selecting provably secure parameters.
   */
  @FXML
  private RadioButton provablySecureParametersRadio;

  /**
   * Radio button for selecting provably secure parameters.
   */
  @FXML
  private RadioButton customParametersRadio;

  /**
   * TextField for entering the hash output size. Initially hidden and managed based on the selected
   * hash function.
   */
  @FXML
  private TextArea hashOutputSizeField;

  @FXML
  private TextField hashOutputSizeStandardMode;

  /**
   * VBox containing elements for message input in standard mode. This includes the text area for
   * inputting or importing the text to be signed.
   */
  @FXML
  private VBox standardModeMessageVBox;


  /**
   * VBox containing elements for message batch input in benchmarking mode. This includes fields for
   * importing and managing message batches for signature benchmarking.
   */
  @FXML
  private VBox benchmarkingModeMessageVBox;


  /**
   * Label associated with the keyField TextField. Displays a description or instruction related to
   * the private key input field.
   */
  @FXML
  private Label keyFieldLabel;

  /**
   * Horizontal Box containing options on whether to instantiate a scheme with provably secure
   * parameters on the occasion that a key has been pre-loaded (not selected by the user) as a
   * consequence of the key generation process.
   */
  @FXML
  private HBox provableParamsHbox;

  /**
   * Radio Button for opting out of Cross-Parameter mode.
   */
  @FXML
  private RadioButton noCrossParameterRadio;

  /**
   * Radio Button for opting into Cross-Parameter mode.
   */
  @FXML
  private RadioButton yesCrossParameterRadio;

  /**
   * Toggle Group for selecting between standard and provably secure parameters.
   */
  @FXML
  private ToggleGroup provableParamsToggleGroup;

  /**
   * Horizontal Box for toggling Cross-Parameter Benchmarking Mode.
   */
  @FXML
  private HBox crossParameterHbox;

  /**
   * Toggle Switch for enabling or disabling Cross-Parameter Benchmarking Mode.
   */
  @FXML
  private ToggleSwitch crossParameterBenchmarkingModeToggle;

  /**
   * Horizontal Box containing elements for setting the hash function size.
   */
  @FXML
  private HBox hashFunctionSizeHbox;

  /**
   * Horizontal Box containing options for the hash type to be used under standard parameters in the
   * * cross-parameter benchmarking/comparison mode.
   */
  @FXML
  private HBox standardHashChoiceComparisonModeHbox;

  /**
   * Horizontal Box containing options for the hash type to be used under provably secure parameters
   * in the * cross-parameter benchmarking/comparison mode.
   */
  @FXML
  private HBox provableHashChoiceComparisonModeHbox;

  /**
   * Horizontal Box containing options for hash function choice in benchmarking and standard modes.
   */
  @FXML
  private HBox generalHashFunctionHbox;

  /**
   * Check ComboBox for selecting a hash function to be used under provably secure parameters in the
   * cross-parameter benchmarking/comparison mode.
   */
  @FXML
  private CheckComboBox<String> provableHashFunctionComboBox;

  /**
   * Check ComboBox for selecting a hash function to be used under standard parameters in the
   * cross-parameter benchmarking/comparison mode.
   */
  @FXML
  private CheckComboBox<String> fixedHashFunctionComboBox;


  /**
   * Initialises the SignView, setting up the toggle group for parameter choice.
   */
  public void initialize() {
    updateHashFunctionDropdownForStandard();
    parameterChoiceToggleGroup = new ToggleGroup();
    standardParametersRadio.setToggleGroup(parameterChoiceToggleGroup);
    provablySecureParametersRadio.setToggleGroup(parameterChoiceToggleGroup);
    customParametersRadio.setToggleGroup(parameterChoiceToggleGroup);

    provableParamsToggleGroup = new ToggleGroup();
    noCrossParameterRadio.setToggleGroup(provableParamsToggleGroup);
    yesCrossParameterRadio.setToggleGroup(provableParamsToggleGroup);
    // Populate the CheckComboBox for standard parameters
    fixedHashFunctionComboBox.getItems().addAll("SHA-256", "SHA-512");

    // Populate the CheckComboBox for provable parameters
    provableHashFunctionComboBox.getItems()
        .addAll("SHA-256 with MGF1", "SHA-512 with MGF1", "SHAKE-128", "SHAKE-256");

  }


  /**
   * Retrieves the parameter choice selected by the user, which relates to the potential hash size
   * chosen for the selected signature scheme.
   *
   * @return A String representing the parameter choice.
   */
  public String getParameterChoice() {
    RadioButton selectedButton = (RadioButton) parameterChoiceToggleGroup.getSelectedToggle();
    return selectedButton != null ? selectedButton.getText() : "";
  }


  /**
   * Gets the image view showing a checkmark next to the text file, indicating a successful load.
   *
   * @return ImageView for the text file checkmark.
   */
  public ImageView getTextFileCheckmarkImage() {
    return textFileCheckmarkImage;
  }

  /**
   * Sets the image for the text file checkmark to indicate the status of the text file import.
   */
  public void setTextFileCheckmarkImage() {
    this.textFileCheckmarkImage.setImage(new Image("/checkmark.png"));

    // Set the ImageView size
    this.textFileCheckmarkImage.setFitWidth(20);
    this.textFileCheckmarkImage.setFitHeight(20);

    // Preserve the image's aspect ratio
    this.textFileCheckmarkImage.setPreserveRatio(true);
  }

  /**
   * Sets the image for the text file checkmark to indicate the status of message batch file
   * import.
   */
  public void setCheckmarkImageMessageBatch() {
    this.checkmarkImageMessageBatch.setImage(new Image("/checkmark.png"));

    // Set the ImageView size
    this.checkmarkImageMessageBatch.setFitWidth(20);
    this.checkmarkImageMessageBatch.setFitHeight(20);

    // Preserve the image's aspect ratio
    this.checkmarkImageMessageBatch.setPreserveRatio(true);
  }

  /**
   * Sets the visibility of the image for the checkmark to indicate the status of the import of a
   * message.
   */
  public void setTextFieldCheckmarkImageVisibility(boolean visible) {
    this.textFileCheckmarkImage.setVisible(visible);
  }

  /**
   * Gets the ImageView that shows the checkmark that indicates the success in importing a private
   * key.
   *
   * @return The ImageView with the checkmark.
   */
  public ImageView getCheckmarkImage() {
    return checkmarkImage;
  }

  /**
   * Sets the image for the checkmark to indicate the status of the private key import.
   */
  public void setCheckmarkImage() {
    this.checkmarkImage.setImage(new Image("/checkmark.png"));
    // Set the ImageView size
    this.checkmarkImage.setFitWidth(20);
    this.checkmarkImage.setFitHeight(20);
    // Preserve the image's aspect ratio
    this.checkmarkImage.setPreserveRatio(true);
  }

  /**
   * Sets the visibility of the checkmark image, indicating the status of the private key import.
   *
   * @param visible true to make the checkmark visible, false to hide it.
   */
  public void setCheckmarkImageVisibility(boolean visible) {
    this.checkmarkImage.setVisible(visible);
  }

  /**
   * Sets the visibility of the notification pane, which shows the results of the signature
   * operation.
   *
   * @param visible true to make the pane visible, false to hide it.
   */
  public void setNotificationPaneVisible(boolean visible) {
    this.notificationPane.setVisible(visible);
  }


  /**
   * Retrieves the text from the textInput TextField which represents the message to be signed,
   * entered or selected by the user.
   *
   * @return A String representing the key.
   */
  public String getTextInput() {
    return textInput.getText();
  }

  /**
   * Sets the text of the TextField for providing a message to be signed.
   *
   * @param text A String representing the message to be set in the TextField.
   */
  public void setTextInput(String text) {
    this.textInput.setText(text);
  }

  /**
   * Sets the visibility of the text input TextArea.
   *
   * @param visible true to make the text area visible, false to hide it.
   */
  public void setTextInputVisibility(boolean visible) {
    this.textInput.setVisible(visible);
    this.textInput.setManaged(visible);
  }

  /**
   * Sets the visibility of the HBox containing the text input components.
   *
   * @param visible true to make the HBox visible, false to hide it.
   */
  public void setTextInputHBoxVisibility(boolean visible) {
    this.textInputHBox.setVisible(visible);
    this.textInputHBox.setManaged(visible);
  }

  /**
   * Retrieves the text from the keyField TextField which represents the key entered or selected by
   * the user.
   *
   * @return A String representing the key.
   */
  public String getKey() {
    return keyField.getText();
  }

  /**
   * Sets the text of the keyField TextField to the specified key.
   *
   * @param key A String representing the key to be set in the TextField.
   */
  public void setKey(String key) {
    this.keyField.setText(key);
  }

  /**
   * Sets the text of the keyFieldLabel. This method updates the label text associated with the
   * keyField, providing instructions or descriptions.
   *
   * @param text The text to set for the label.
   */
  public void setKeyLabel(String text) {
    this.keyFieldLabel.setText(text);
  }

  /**
   * Sets the visibility of the keyField TextField.
   *
   * @param visible true if the keyField should be visible, false otherwise.
   */
  public void setKeyVisibility(boolean visible) {
    this.keyField.setVisible(visible);
  }

  /**
   * Retrieves the currently selected signature scheme from the signatureSchemeDropdown ComboBox.
   *
   * @return string representing the selected signature scheme.
   */
  public String getSelectedSignatureScheme() {
    return signatureSchemeDropdown.getValue();
  }

  /**
   * Sets the selected signature scheme in the signatureSchemeDropdown ComboBox.
   *
   * @param scheme string representing the signature scheme to be selected.
   */
  public void setSelectedSignatureScheme(String scheme) {
    signatureSchemeDropdown.setValue(scheme);
  }

  /**
   * Retrieves the currently selected hash function from the hashFunctionDropdown ComboBox.
   *
   * @return string representing the selected hash function.
   */
  public String getSelectedHashFunction() {
    return hashFunctionDropdown.getValue();
  }


  /**
   * Sets the selected hash function from the hashFunctionDropdown ComboBox.
   *
   * @param hashFunction string representing the signature scheme to be selected.
   */
  public void setSelectedHashFunction(String hashFunction) {
    hashFunctionDropdown.setValue(hashFunction);
  }


  /**
   * Retrieves the text from the textFileNameLabel Label which displays the name of the imported
   * text file.
   *
   * @return A String representing the file name.
   */
  public String getTextFileNameLabel() {
    return textFileNameLabel.getText();
  }

  /**
   * Sets the text of the textFileNameLabel Label to the specified file name.
   *
   * @param fileName A String representing the name of the file to be displayed.
   */
  public void setTextFileNameLabel(String fileName) {
    this.textFileNameLabel.setText(fileName);
  }

  /**
   * Sets the label of the importTextButton Button to the specified text.
   *
   * @param label A String to be set as the button's label.
   */
  public void setImportTextButtonLabel(String label) {
    this.importTextButton.setText(label);
  }

  /**
   * Retrieves the label text of the importTextButton Button.
   *
   * @return A String representing the button's label.
   */
  public String getImportTextButtonLabel() {
    return this.importTextButton.getText();
  }

  /**
   * Retrieves the notificationPane StackPane which is used to display signature generation
   * completion status.
   *
   * @return The notificationPane StackPane.
   */
  public StackPane getNotificationPane() {
    return notificationPane;
  }


  /**
   * Sets the visibility of the benchmarking mode toggle switch and manages its properties.
   *
   * @param visible true to make the benchmarking mode toggle switch visible, false to hide it.
   */
  public void setBenchmarkingModeToggleVisibility(boolean visible) {
    benchmarkingModeToggle.setVisible(visible);
    benchmarkingModeToggle.setManaged(visible);
  }

  /**
   * Sets the visibility of the numMessageLabel, numMessageField, and manages their properties.
   *
   * @param visible true to make the numMessageLabel and numMessageField visible, false to hide
   *                them.
   */
  public void setNumMessageVisibility(boolean visible) {
    numMessageLabel.setVisible(visible);
    numMessageLabel.setManaged(visible);
    numMessageField.setVisible(visible);
    numMessageField.setManaged(visible);
  }

  /**
   * Retrieves the text from the numMessageField TextField, which specifies the number of messages
   * for benchmarking.
   *
   * @return The text from the numMessageField.
   */
  public String getNumMessageField() {
    return numMessageField.getText();
  }

  /**
   * Sets whether the numMessageField TextField is editable.
   *
   * @param editable true to make the field editable, false otherwise.
   */
  public void setNumMessageFieldEditable(boolean editable) {
    numMessageField.setEditable(editable);
  }

  /**
   * Clears the text from the numMessageField TextField and makes it editable.
   */
  public void clearNumMessageField() {
    numMessageField.clear();
    numMessageField.setEditable(true);
  }

  /**
   * Sets the visibility of the messageBatchHBox and manages its properties.
   *
   * @param visible true to make the messageBatchHBox visible, false to hide it.
   */
  public void setMessageBatchHBoxVisibility(boolean visible) {
    messageBatchHBox.setVisible(visible);
    messageBatchHBox.setManaged(visible);
  }

  /**
   * Sets the visibility of the messageBatchText and manages its properties.
   *
   * @param visible true to make the messageBatchText visible, false to hide it.
   */
  public void setMessageBatchTextVisibility(boolean visible) {
    messageBatchText.setVisible(visible);
    messageBatchText.setManaged(visible);
  }

  /**
   * Sets the visibility of the messageBatchField and manages its properties.
   *
   * @param visible true to make the messageBatchField visible, false to hide it.
   */
  public void setMessageBatchFieldVisibility(boolean visible) {
    messageBatchField.setVisible(visible);
    messageBatchField.setManaged(visible);
  }

  /**
   * Sets the prompting text of the messageBatchField to urge the user to import a message batch
   *
   * @param text String representing the prompting text.
   */
  public void setMessageBatch(String text) {
    messageBatchField.setText(text);
  }

  /**
   * Sets the visibility of the hash output size area.
   *
   * @param visible true to make the field visible, false to hide it.
   */
  public void setHashOutputSizeFieldVisibility(boolean visible) {
    if (visible) {
      resetHash();
    }
    hashOutputSizeStandardMode.setManaged(visible);
    hashOutputSizeStandardMode.setVisible(visible);

  }


  /**
   * Retrieves the visibility status of the hash output size area.
   *
   * @return true if the hash output size field is visible, false otherwise.
   */
  public boolean getHashOutputSizeAreaVisibility() {
    return hashOutputSizeField.isVisible();

  }

  /**
   * Resets the hash output size area to its initial state with prompt text.
   */
  public void resetHashArea() {
    hashOutputSizeField.setText("");
  }

  /**
   * Resets the hash output size field to its initial state with prompt text.
   */
  public void resetHash() {
    hashOutputSizeStandardMode.setText("");
  }

  /**
   * Retrieves the entered hash output fraction from the area.
   *
   * @return String representing the hash output size.
   */
  public String getHashOutputSizeArea() {
    return hashOutputSizeField.getText();
  }

  /**
   * Retrieves the entered hash output size from the field.
   *
   * @return String representing the hash output size.
   */
  public String getHashOutputSizeField() {
    return hashOutputSizeStandardMode.getText();
  }

  /**
   * Sets the visibility of the hash output size field.
   *
   * @param visible true to make the field visible, false to hide it.
   */
  public void setHashOutputSizeAreaVisibility(boolean visible) {
    if (visible) {
      resetHashArea();
    }
    hashOutputSizeField.setManaged(visible);
    hashOutputSizeField.setVisible(visible);

  }


  /**
   * Retrieves the visibility status of the hash output size field.
   *
   * @return true if the hash output size field is visible, false otherwise.
   */
  public boolean getHashOutputSizeFieldVisibility() {
    return hashOutputSizeStandardMode.isVisible();

  }

  /**
   * Resets the hash output size field to its initial state with prompt text.
   */
  public void resetHashField() {
    hashOutputSizeStandardMode.setText("");
  }

  /**
   * Retrieves the entered hash output size from the field.
   *
   * @return String representing the hash output size.
   */
  public String getHashOutputSize() {
    return hashOutputSizeStandardMode.getText();
  }

  /**
   * Sets the visibility of the checkmarkImageMessageBatch and manages its properties.
   *
   * @param visible true to make the checkmarkImageMessageBatch visible, false to hide it.
   */
  public void setCheckmarkImageMessageBatchVisibility(boolean visible) {
    checkmarkImageMessageBatch.setVisible(visible);
    checkmarkImageMessageBatch.setManaged(visible);
  }

  /**
   * Sets the visibility of the importTextBatchBtn and manages its properties.
   *
   * @param visible true to make the importTextBatchBtn visible, false to hide it.
   */
  public void setImportTextBatchBtnVisibility(boolean visible) {
    importTextBatchBtn.setVisible(visible);
    importTextBatchBtn.setManaged(visible);
  }

  /**
   * Sets the visibility of the importTextButton. This method controls whether the button for
   * importing a message in standard mode is visible to the user.
   *
   * @param visible true to make the button visible, false to hide it.
   */
  public void setImportTextButtonVisibility(boolean visible) {
    importTextButton.setVisible(visible);
    importTextButton.setManaged(visible);
  }

  /**
   * Sets the visibility of the cancelImportTextBatchButton and manages its properties.
   *
   * @param visible true to make the cancelImportTextBatchButton visible, false to hide it.
   */
  public void setCancelImportTextBatchButtonVisibility(boolean visible) {
    cancelImportTextBatchButton.setVisible(visible);
    cancelImportTextBatchButton.setManaged(visible);
  }

  /**
   * Sets the visibility of the cancelImportTextButton. This method controls whether the button for
   * canceling the import of a message in standard mode is visible to the user.
   *
   * @param visible true to make the button visible, false to hide it.
   */
  public void setCancelImportTextButtonVisibility(boolean visible) {
    cancelImportTextButton.setVisible(visible);
    cancelImportTextButton.setManaged(visible);
  }

  /**
   * Sets the visibility of the importKeyBatchButton and manages its properties.
   *
   * @param visible true to make the importKeyBatchButton visible, false to hide it.
   */
  public void setImportKeyBatchButtonVisibility(boolean visible) {
    importKeyBatchButton.setVisible(visible);
    importKeyBatchButton.setManaged(visible);
  }

  /**
   * Sets the visibility of the importKeyButton. This method controls whether the button for
   * importing a key during standard mode is visible to the user.
   *
   * @param visible true to make the button visible, false to hide it.
   */
  public void setImportKeyButtonVisibility(boolean visible) {
    importKeyButton.setVisible(visible);
    importKeyButton.setManaged(visible);
  }

  /**
   * Sets the visibility of the cancelImportKeyButton and manages its properties.
   *
   * @param visible true to make the cancelImportKeyButton visible, false to hide it.
   */
  public void setCancelImportKeyButtonVisibility(boolean visible) {
    cancelImportKeyButton.setVisible(visible);
    cancelImportKeyButton.setManaged(visible);
  }

  /**
   * Sets the visibility of the cancelImportSingleKeyButton. This method controls whether the button
   * for canceling the import of a single key in standard mode is visible to the user.
   *
   * @param visible true to make the button visible, false to hide it.
   */
  public void setCancelImportSingleKeyButtonVisibility(boolean visible) {
    cancelImportSingleKeyButton.setVisible(visible);
    cancelImportSingleKeyButton.setManaged(visible);
  }


  /**
   * Updates the hash function dropdown options for custom or provably secure parameter selections.
   */
  public void updateHashFunctionDropdownForCustomOrProvablySecure() {
    hashFunctionDropdown.setItems(FXCollections.observableArrayList(
        "SHA-256 with MGF1",
        "SHA-512 with MGF1",
        "SHAKE-128",
        "SHAKE-256"
    ));
  }

  /**
   * Updates the hash function dropdown options for standard parameter selections.
   */
  public void updateHashFunctionDropdownForStandard() {
    hashFunctionDropdown.setItems(FXCollections.observableArrayList(
        "SHA-256",
        "SHA-512"
    ));
  }


  /**
   * Registers an observer for the event of importing text. The observer is triggered when the user
   * interacts with the import text button.
   *
   * @param observer the event handler to be invoked on text import action.
   */
  public void addImportTextObserver(EventHandler<ActionEvent> observer) {
    importTextButton.setOnAction(observer);
  }

  /**
   * Registers an observer for the create signature button click action.
   *
   * @param observer The event handler to register.
   */
  void addCreateSignatureObserver(EventHandler<ActionEvent> observer) {
    createSignatureButton.setOnAction(observer);
  }

  /**
   * Registers an observer for the back to main menu button click action.
   *
   * @param observer The event handler to register.
   */
  public void addBackToMainMenuObserver(EventHandler<ActionEvent> observer) {
    backToMainMenuButton.setOnAction(observer);
  }

  /**
   * Registers an observer for the help button click action.
   *
   * @param observer The event handler to register.
   */
  public void addHelpObserver(EventHandler<ActionEvent> observer) {
    helpButton.setOnAction(observer);
  }

  /**
   * Registers an observer for the import key button click action.
   *
   * @param observer The event handler to register.
   */
  public void addImportKeyObserver(EventHandler<ActionEvent> observer) {
    importKeyButton.setOnAction(observer);
  }


  /**
   * Registers an observer for when the signature scheme dropdown value changes.
   *
   * @param observer The change listener to register.
   */
  public void addSignatureSchemeChangeObserver(ChangeListener<String> observer) {
    signatureSchemeDropdown.valueProperty().addListener(observer);
  }

  /**
   * Registers an observer for changes in the selected hash function from the hash function
   * dropdown.
   *
   * @param observer The change listener to be registered.
   */
  public void addHashFunctionChangeObserver(ChangeListener<String> observer) {
    hashFunctionDropdown.valueProperty().addListener(observer);
  }

  /**
   * Registers an observer for changes in the parameter choice selection.
   *
   * @param observer The change listener to be registered.
   */
  public void addParameterChoiceChangeObserver(ChangeListener<Toggle> observer) {
    parameterChoiceToggleGroup.selectedToggleProperty().addListener(observer);
  }


  /**
   * Registers an observer for the importTextBatchBtn Button's action event.
   *
   * @param observer The event handler to be registered.
   */
  public void addImportTextBatchBtnObserver(EventHandler<ActionEvent> observer) {
    importTextBatchBtn.setOnAction(observer);
  }

  /**
   * Registers an observer for the cancelImportTextButton Button's action event. This observer is
   * called when the user clicks the button to cancel the import of a text batch in benchmarking
   * mode.
   *
   * @param observer The event handler to be registered.
   */
  public void addCancelImportTextBatchButtonObserver(EventHandler<ActionEvent> observer) {
    cancelImportTextBatchButton.setOnAction(observer);
  }

  /**
   * Registers an observer for the cancelImportTextButton's action event. This observer is invoked
   * when the user clicks the button to cancel the import of a single message in the applications
   * standard mode.
   *
   * @param observer The event handler to be registered.
   **/
  public void addCancelImportTextButtonObserver(EventHandler<ActionEvent> observer) {
    cancelImportTextButton.setOnAction(observer);
  }

  /**
   * Registers an observer for the importKeyBatchButton Button's action event. This observer is
   * invoked when the user clicks the button to import a batch of keys.
   *
   * @param observer The event handler to be registered.
   */
  public void addImportKeyBatchButtonObserver(EventHandler<ActionEvent> observer) {
    importKeyBatchButton.setOnAction(observer);
  }

  /**
   * Registers an observer for the cancelImportKeyButton Button's action event.
   *
   * @param observer The event handler to be registered.
   */
  public void addCancelImportKeyButtonObserver(EventHandler<ActionEvent> observer) {
    cancelImportKeyButton.setOnAction(observer);
  }

  /**
   * Registers an observer for the cancelImportSingleKeyButton's action event. This observer is
   * called when the user clicks the button to cancel the import of a single key.
   *
   * @param observer The event handler to be registered.
   */
  public void addCancelImportSingleKeyButtonObserver(EventHandler<ActionEvent> observer) {
    cancelImportSingleKeyButton.setOnAction(observer);
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
   * Registers an observer for the closeNotificationButton Button's action event.
   *
   * @param observer The event handler to be registered.
   */
  public void addCloseNotificationObserver(EventHandler<ActionEvent> observer) {
    closeNotificationButton.setOnAction(observer);
  }

  /**
   * Shows the notification pane, disabling interaction with other UI components to focus user
   * attention on the notification for a completed signature generation process.
   */
  public void showNotificationPane() {
    // Disable all sibling nodes of notificationPane
    for (Node child : root.getChildren()) {
      if (child != notificationPane) {
        child.setDisable(true);
      }
    }
    // Ensure the notificationPane itself remains enabled
    notificationPane.setVisible(true);
    notificationPane.setDisable(false);
  }

  /**
   * Sets the visibility of the standardModeMessageVBox.
   *
   * @param visible true to make the VBox visible, false to hide it.
   */
  public void setStandardModeMessageVBoxVisibility(boolean visible) {
    standardModeMessageVBox.setVisible(visible);
    standardModeMessageVBox.setManaged(visible);
  }

  /**
   * Sets the visibility of the benchmarkingModeMessageVBox.
   *
   * @param visible true to make the VBox visible, false to hide it.
   */
  public void setBenchmarkingModeMessageVBoxVisibility(boolean visible) {
    benchmarkingModeMessageVBox.setVisible(visible);
    benchmarkingModeMessageVBox.setManaged(visible);
  }


  /**
   * Sets the visibility of the createSignatureButton.
   *
   * @param visible true to make the button visible, false to hide it.
   */
  public void setCreateSignatureButtonVisibility(boolean visible) {
    createSignatureButton.setManaged(visible);
    createSignatureButton.setVisible(visible);
  }

  /**
   * Checks if Benchmarking Mode is enabled.
   *
   * @return true if Benchmarking Mode is selected, false otherwise.
   */
  public boolean isBenchmarkingModeEnabled() {
    return benchmarkingModeToggle.isSelected();
  }

  /**
   * Sets the visibility of the provable parameters options horizontal box.
   *
   * @param visible true to make the box visible, false to hide it.
   */
  public void setProvableParamsHboxVisibility(boolean visible) {
    this.provableParamsHbox.setVisible(visible);
    this.provableParamsHbox.setManaged(visible);
  }

  /**
   * Sets the visibility of the cross-parameter horizontal box.
   *
   * @param visible true to make the box visible, false to hide it.
   */
  public void setCrossParameterHboxVisibility(boolean visible) {
    this.crossParameterHbox.setManaged(visible);
    this.crossParameterHbox.setVisible(visible);
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
   * Sets the visibility of the standard parameters radio button.
   *
   * @param visible true to make the radio button visible, false to hide it.
   */
  public void setStandardParametersRadioVisibility(boolean visible) {
    this.standardParametersRadio.setManaged(visible);
    this.standardParametersRadio.setVisible(visible);
  }

  /**
   * Sets the visibility of the custom parameters radio button.
   *
   * @param visible true to make the radio button visible, false to hide it.
   */
  public void setCustomParametersRadioVisibility(boolean visible) {
    this.customParametersRadio.setManaged(visible);
    this.customParametersRadio.setVisible(visible);
  }

  /**
   * Sets the selected state of the provably secure parameters radio button.
   *
   * @param visible true to select the radio button, false otherwise.
   */
  public void setProvablySecureParametersRadioSelected(boolean visible) {
    provablySecureParametersRadio.setSelected(visible);
  }

  /**
   * Adds an observer for changes in the provable scheme selection.
   *
   * @param observer the observer to be notified when the scheme selection changes.
   */
  public void addProvableSchemeChangeObserver(ChangeListener<Toggle> observer) {
    provableParamsToggleGroup.selectedToggleProperty().addListener(observer);
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
   * Sets the visibility of the hash function size horizontal box.
   *
   * @param visible true to make the box visible, false to hide it.
   */
  public void setHashFunctionSizeHboxVisibility(boolean visible) {
    hashFunctionSizeHbox.setVisible(visible);
    hashFunctionSizeHbox.setManaged(visible);
  }

  /**
   * Sets the visibility of the standard hash choice comparison mode horizontal box.
   *
   * @param visible true to make the box visible, false to hide it.
   */
  public void setStandardHashChoiceComparisonModeHboxVisibility(boolean visible) {
    standardHashChoiceComparisonModeHbox.setVisible(visible);
    standardHashChoiceComparisonModeHbox.setManaged(visible);
  }

  /**
   * Sets the visibility of the provable hash choice comparison mode horizontal box.
   *
   * @param visible true to make the box visible, false to hide it.
   */
  public void setProvableHashChoiceComparisonModeHboxVisibility(boolean visible) {
    provableHashChoiceComparisonModeHbox.setVisible(visible);
    provableHashChoiceComparisonModeHbox.setManaged(visible);
  }

  /**
   * Sets the visibility of the general hash function horizontal box.
   *
   * @param visible true to make the box visible, false to hide it.
   */
  public void setGeneralHashFunctionHboxVisibility(boolean visible) {
    generalHashFunctionHbox.setVisible(visible);
    generalHashFunctionHbox.setManaged(visible);
  }

  /**
   * Registers an observer for when the standard parameter instantiation CheckComboBox values
   * change.
   *
   * @param observer The change listener to register.
   */
  public void addStandardHashFunctionChangeObserver(ListChangeListener<String> observer) {
    fixedHashFunctionComboBox.getCheckModel().getCheckedItems().addListener(observer);
  }

  /**
   * Registers an observer for when the provably secure parameter instantiation CheckComboBox values
   * change.
   *
   * @param observer The change listener to register.
   */
  public void addProvableHashFunctionChangeObserver(ListChangeListener<String> observer) {
    provableHashFunctionComboBox.getCheckModel().getCheckedItems().addListener(observer);
  }

}
