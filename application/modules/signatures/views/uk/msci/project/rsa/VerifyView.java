package uk.msci.project.rsa;

import javafx.beans.InvalidationListener;
import javafx.beans.value.ChangeListener;
import javafx.collections.FXCollections;
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
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import org.controlsfx.control.ToggleSwitch;
import uk.msci.project.rsa.SignatureBaseController.SignatureSchemeChangeObserver;

/**
 * The {@code VerifyView} class is responsible for managing the user interface related to the
 * verification process in the Signature Scheme POC application.
 */
public class VerifyView implements SignatureViewInterface {

  // The root pane of the verification view
  @FXML
  private AnchorPane root;

  // Labels for indicating the result of the signature verification
  @FXML
  private Label falseLabel; // Indicates a failed verification
  @FXML
  private Label trueLabel;  // Indicates a successful verification

  // Label and image for displaying the name and status of the imported text file
  @FXML
  private Label textFileNameLabel;
  @FXML
  private ImageView textFileCheckmarkImage;

  // HBox containers for input fields and their corresponding checkmark images
  @FXML
  private HBox textInputHBox; // Container for the text input area and file name label
  @FXML
  private HBox sigFileHBox;   // Container for the signature input area and file name label

  // TextArea for user to input or import the text that the signature will verify
  @FXML
  private TextArea textInput;

  // VBox container for recovery options, shown after verification
  @FXML
  private VBox recoveryOptions;

  // Button to trigger the import of text for verification
  @FXML
  private Button importTextButton;

  // TextField for displaying the name of the imported public key file
  @FXML
  private TextField keyField;
  // Button to trigger the import of the public key
  @FXML
  private Button importKeyButton;
  // Checkmark image indicating the public key has been successfully imported
  @FXML
  private ImageView checkmarkImage;

  // TextArea for user to input or import the signature to be verified
  @FXML
  private TextArea signatureText;
  // Label for displaying the name of the imported signature file
  @FXML
  private Label sigFileNameLabel;
  // Checkmark image indicating the signature has been successfully imported
  @FXML
  private ImageView sigFileCheckmarkImage;
  // Button to trigger the import of the signature
  @FXML
  private Button importSigButton;

  // ComboBox for selecting the signature scheme to use for verification
  @FXML
  private ComboBox<String> signatureSchemeDropdown;

  /**
   * ComboBox to allow the selection of a hash function from predefined options.
   */
  @FXML
  private ComboBox<String> hashFunctionDropdown;

  // Button to initiate the verification of the signature
  @FXML
  private Button verifyBtn;

  // Navigation and help buttons
  @FXML
  private Button backToMainMenuButton;
  @FXML
  private Button helpButton;

  // StackPane for displaying notifications such as success or failure messages
  @FXML
  private StackPane notificationPane;
  // Buttons within the notification pane for actions related to the recoverable message
  @FXML
  private Button exportRecoverableMessageButton;
  @FXML
  private Button copyRecoverableMessageButton;
  // Button to close the notification pane
  @FXML
  private Button closeNotificationButton;

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
   * Button for importing text batch.
   */
  @FXML
  private Button importTextBatchBtn;

  /**
   * Button for canceling text batch import.
   */
  @FXML
  private Button cancelImportTextButton;

  @FXML
  private Label signatureBatchText;

  @FXML
  private TextField signatureField;

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

  @FXML
  private Button verificationBenchmarkButton;

  @FXML
  private Button importSigBatchButton;

  @FXML
  private Button cancelImportSigBatchButton;

  /**
   * Toggle switch for enabling or disabling benchmarking mode.
   */
  @FXML
  private ToggleSwitch benchmarkingModeToggle;

  /**
   * TextField for entering the hash output size. Initially hidden and managed based on the selected
   * hash function.
   */
  @FXML
  private TextField hashOutputSizeField;

  @FXML
  private HBox signatureBatchHBox;

  /**
   * Initialises the Verification view, setting up the toggle group for parameter choice.
   */
  public void initialize() {
    updateHashFunctionDropdownForStandard();
    parameterChoiceToggleGroup = new ToggleGroup();
    standardParametersRadio.setToggleGroup(parameterChoiceToggleGroup);
    provablySecureParametersRadio.setToggleGroup(parameterChoiceToggleGroup);
    customParametersRadio.setToggleGroup(parameterChoiceToggleGroup);
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
   * Sets the visibility of the image for the checkmark to indicate the status of the import of a
   * message.
   */
  public void setTextFieldCheckmarkImageVisibility(boolean visible) {
    this.textFileCheckmarkImage.setVisible(visible);
  }

  /**
   * Gets the ImageView that shows the checkmark that indicates the success in importing a public
   * key.
   *
   * @return The ImageView with the checkmark.
   */
  public ImageView getCheckmarkImage() {
    return checkmarkImage;
  }

  /**
   * Sets the image for the checkmark to indicate the status of the public key import.
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
   * Sets the visibility of the checkmark image, indicating the status of the public key import.
   *
   * @param visible true to make the checkmark visible, false to hide it.
   */
  public void setCheckmarkImageVisibility(boolean visible) {
    this.checkmarkImage.setVisible(visible);
  }

  /**
   * Sets the visibility of the HBox that contains the signature file information.
   *
   * @param visible true to show the HBox, false to hide it.
   */
  public void setSigFileHBoxVisibility(boolean visible) {
    this.sigFileHBox.setVisible(visible);
  }

  /**
   * Sets the visibility of the signature file checkmark image.
   *
   * @param visible true to show the checkmark, false to hide it.
   */

  public void setSigFileCheckmarkImageVisibility(boolean visible) {
    this.sigFileCheckmarkImage.setVisible(visible);
  }

  /**
   * Sets the visibility of the label indicating a successful verification.
   *
   * @param visible true to show the label, false to hide it.
   */
  public void setTrueLabelVisibility(boolean visible) {
    this.trueLabel.setVisible(visible);
  }

  /**
   * Sets the visibility of the label indicating a failed verification.
   *
   * @param visible true to show the label, false to hide it.
   */
  public void setFalseLabelVisibility(boolean visible) {
    this.falseLabel.setVisible(visible);
  }

  /**
   * Gets the ImageView that shows the checkmark that indicates the success in importing a
   * signature
   *
   * @return The ImageView with the checkmark.
   */
  public ImageView getSigFileCheckmarkImage() {
    return sigFileCheckmarkImage;
  }

  /**
   * Sets the image of the signature file checkmark ImageView to a checkmark, indicating successful
   * import.
   */
  public void setSigFileCheckmarkImage() {
    this.sigFileCheckmarkImage.setImage(new Image("/checkmark.png"));
    // Set the ImageView size
    this.sigFileCheckmarkImage.setFitWidth(20);
    this.sigFileCheckmarkImage.setFitHeight(20);
    // Preserve the image's aspect ratio
    this.sigFileCheckmarkImage.setPreserveRatio(true);
  }


  /**
   * Sets the image for the text file checkmark to indicate the status of the text file import.
   *
   * @param image The Image to be set on the text file checkmark ImageView.
   */
  public void setTextFileCheckmarkImage(Image image) {
    this.textFileCheckmarkImage.setImage(image);
  }


  /**
   * Sets the image for the checkmark to indicate the status of the public key import.
   *
   * @param image The Image to be set on the checkmark ImageView.
   */
  public void setCheckmarkImage(Image image) {
    this.checkmarkImage.setImage(image);
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
   * Sets the text input area with the provided text.
   *
   * @param text The text to set in the text input area.
   */
  public void setTextInput(String text) {
    this.textInput.setText(text);
  }

  /**
   * Sets the visibility of the text input area.
   *
   * @param visible true to show the text input area, false to hide it.
   */
  public void setTextInputVisibility(boolean visible) {
    this.textInput.setVisible(visible);
  }

  /**
   * Sets the visibility of the HBox containing the text input area.
   *
   * @param visible true to show the HBox, false to hide it.
   */
  public void setTextInputHBoxVisibility(boolean visible) {
    this.textInputHBox.setVisible(visible);
  }

  /**
   * Gets the text currently being provided as a signature
   *
   * @return the potential signature candidate
   */
  public String getSigText() {
    return signatureText.getText();
  }

  /**
   * Sets the signature text area with the provided signature text.
   *
   * @param text The signature text to set in the signature text area.
   */
  public void setSignatureText(String text) {
    this.signatureText.setText(text);
  }

  /**
   * Sets the visibility of the signature text area.
   *
   * @param visible true to show the signature text area, false to hide it.
   */
  public void setSignatureTextVisibility(boolean visible) {
    this.signatureText.setVisible(visible);
  }

  public String getKey() {
    return keyField.getText();
  }

  /**
   * Sets the TextField for the key with the provided key text.
   *
   * @param key The key text to set in the key TextField.
   */
  public void setKey(String key) {
    this.keyField.setText(key);
  }

  /**
   * Sets the visibility of the key TextField.
   *
   * @param visible true to show the key TextField, false to hide it.
   */
  public void setKeyVisibility(boolean visible) {
    this.keyField.setVisible(visible);
  }

  /**
   * Retrieves the currently selected signature scheme from the signatureSchemeDropdown ComboBox.
   *
   * @return A String representing the selected signature scheme.
   */
  public String getSelectedSignatureScheme() {
    return signatureSchemeDropdown.getValue();
  }

  /**
   * Sets the selected signature scheme in the dropdown.
   *
   * @param scheme The signature scheme to select.
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
   * Sets the file name label with the provided text.
   *
   * @param fileName The file name text to set in the label.
   */
  public void setTextFileNameLabel(String fileName) {
    this.textFileNameLabel.setText(fileName);
  }

  /**
   * Retrieves the text from the sigFileNameLabel Label which displays the name of the imported
   * signature.
   *
   * @return A String representing the file name.
   */
  public String getSigFileNameLabel() {
    return sigFileNameLabel.getText();
  }

  /**
   * Sets the signature file name label with the provided text.
   *
   * @param fileName The signature file name to set in the label.
   */
  public void setSigFileNameLabel(String fileName) {
    this.sigFileNameLabel.setText(fileName);
  }


  public String getImportTextButtonLabel() {
    return this.importTextButton.getText();
  }


  /**
   * Sets the label of the import text button.
   *
   * @param label The label text to set on the import text button.
   */
  public void setImportTextButtonLabel(String label) {
    this.importTextButton.setText(label);
  }


  /**
   * Retrieves the label text of the importSigButton Button.
   *
   * @return A String representing the button's label.
   */
  public String getImportSigButtonLabel() {
    return this.importSigButton.getText();
  }

  /**
   * Sets the label of the import signature button.
   *
   * @param label The label text to set on the import signature button.
   */
  public void setImportSigButtonLabel(String label) {
    this.importSigButton.setText(label);
  }


  /**
   * Sets the visibility of the VBox containing recovery options.
   *
   * @param visible true to show the VBox, false to hide it.
   */
  public void setRecoveryOptionsVisibility(boolean visible) {
    this.recoveryOptions.setVisible(visible);
  }

  /**
   * Retrieves the notificationPane StackPane which is used to display signature verification
   * completion status.
   *
   * @return The notificationPane StackPane.
   */
  public StackPane getNotificationPane() {
    return notificationPane;
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
   * Sets the visibility of the hash output size field.
   *
   * @param visible true to make the field visible, false to hide it.
   */
  public void setHashOutputSizeFieldVisibility(boolean visible) {
    if (visible) {
      resetHashField();
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
    return hashOutputSizeField.isVisible();

  }

  /**
   * Resets the hash output size field to its initial state with prompt text.
   */
  public void resetHashField() {
    hashOutputSizeField.setText("");
  }

  /**
   * Retrieves the entered hash output size from the field.
   *
   * @return String representing the hash output size.
   */
  public String getHashOutputSize() {
    return hashOutputSizeField.getText();
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
   * Sets the visibility of the benchmarking mode toggle switch and manages its properties.
   *
   * @param visible true to make the benchmarking mode toggle switch visible, false to hide it.
   */
  public void setBenchmarkingModeToggleVisibility(boolean visible) {
    benchmarkingModeToggle.setVisible(visible);
    benchmarkingModeToggle.setManaged(visible);
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
   * Sets the visibility of the cancelImportTextButton and manages its properties.
   *
   * @param visible true to make the cancelImportTextButton visible, false to hide it.
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
   * Sets the visibility of the cancelImportKeyButton and manages its properties.
   *
   * @param visible true to make the cancelImportKeyButton visible, false to hide it.
   */
  public void setCancelImportKeyButtonVisibility(boolean visible) {
    cancelImportKeyButton.setVisible(visible);
    cancelImportKeyButton.setManaged(visible);
  }

  /**
   * Sets the visibility of the importSigBatchButton and manages its properties.
   *
   * @param visible true to make the importSigBatchButton visible, false to hide it.
   */
  public void setImportSigBatchBtnVisibility(boolean visible) {
    importSigBatchButton.setVisible(visible);
    importSigBatchButton.setManaged(visible);
  }

  /**
   * Sets the visibility of the CancelImportSigBatchButton and manages its properties.
   *
   * @param visible true to make the CancelImportSigBatchButton visible, false to hide it.
   */
  public void setCancelImportSigBatchButtonVisibility(boolean visible) {
    cancelImportSigBatchButton.setVisible(visible);
    cancelImportSigBatchButton.setManaged(visible);
  }

  /**
   * Sets the visibility of the SigBenchmarkButton and manages its properties.
   *
   * @param visible true to make the SigBenchmarkButton visible, false to hide it.
   */
  public void setVerificationBenchmarkButtonVisibility(boolean visible) {
    verificationBenchmarkButton.setVisible(visible);
    verificationBenchmarkButton.setManaged(visible);
  }

  public void setVerificationButtonVisibility(boolean visible) {
    verifyBtn.setVisible(visible);
    verifyBtn.setManaged(visible);
  }

  /**
   * Sets the visibility of the signatureBatchHBox and manages its properties.
   *
   * @param visible true to make the signatureBatchHBox visible, false to hide it.
   */
  public void setSignatureBatchHBoxVisibility(boolean visible) {
    signatureBatchHBox.setVisible(visible);
    signatureBatchHBox.setManaged(visible);
  }

  /**
   * Sets the visibility of the messageBatchText and manages its properties.
   *
   * @param visible true to make the messageBatchText visible, false to hide it.
   */
  public void setSignatureBatchTextVisibility(boolean visible) {
    signatureBatchText.setVisible(visible);
    signatureBatchText.setManaged(visible);
  }

  /**
   * Sets the visibility of the messageBatchField and manages its properties.
   *
   * @param visible true to make the messageBatchField visible, false to hide it.
   */
  public void setSignatureBatchFieldVisibility(boolean visible) {
    signatureField.setVisible(visible);
    signatureField.setManaged(visible);
  }

  public void setSignatureBatch(String text) {
    signatureField.setText(text);
  }


  /**
   * Registers an observer for the import text button click action.
   *
   * @param observer The event handler to register.
   */
  public void addImportTextObserver(EventHandler<ActionEvent> observer) {
    importTextButton.setOnAction(observer);
  }

  /**
   * Registers an observer for the verify button click action.
   *
   * @param observer The event handler to register.
   */
  void addVerifyBtnObserver(EventHandler<ActionEvent> observer) {
    verifyBtn.setOnAction(observer);
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
   * Registers an observer for the export recoverable message button click action.
   *
   * @param observer The event handler to register.
   */
  void addExportRecoverableMessageObserver(EventHandler<ActionEvent> observer) {
    exportRecoverableMessageButton.setOnAction(observer);
  }

  /**
   * Registers an observer for the copy recoverable message button click action.
   *
   * @param observer The event handler to register.
   */
  void addCopyRecoverableMessageObserver(EventHandler<ActionEvent> observer) {
    copyRecoverableMessageButton.setOnAction(observer);
  }

  /**
   * Registers an observer for the close notification button click action.
   *
   * @param observer The event handler to register.
   */
  public void addCloseNotificationObserver(EventHandler<ActionEvent> observer) {
    closeNotificationButton.setOnAction(observer);
  }


  /**
   * Registers an observer for the import signature button click action.
   *
   * @param observer The event handler to register.
   */
  void addImportSigButtonObserver(EventHandler<ActionEvent> observer) {
    importSigButton.setOnAction(observer);
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
   * called when the user clicks the button to cancel the import of a text batch.
   *
   * @param observer The event handler to be registered.
   */
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
   * Registers an observer for the importSigBatchButton Button's action event. This observer is
   * invoked when the user clicks the button to import a batch of signatures.
   *
   * @param observer The event handler to be registered.
   */
  public void addImportSigBatchButtonObserver(EventHandler<ActionEvent> observer) {
    importSigBatchButton.setOnAction(observer);
  }

  /**
   * Registers an observer for the cancelImportSigBatchButton Button's action event.
   *
   * @param observer The event handler to be registered.
   */
  public void addCancelImportSigBatchButtonObserver(EventHandler<ActionEvent> observer) {
    cancelImportSigBatchButton.setOnAction(observer);
  }

  /**
   * Registers an observer for the verification benchmarking Button's action event.
   *
   * @param observer The event handler to be registered.
   */
  public void addVerificationBenchmarkButtonObserver(EventHandler<ActionEvent> observer) {
    verificationBenchmarkButton.setOnAction(observer);
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
   * Registers an observer for changes in the parameter choice selection.
   *
   * @param observer The change listener to be registered.
   */
  public void addParameterChoiceChangeObserver(ChangeListener<Toggle> observer) {
    parameterChoiceToggleGroup.selectedToggleProperty().addListener(observer);
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
   * Shows the notification pane, disabling interaction with other UI components to focus user
   * attention on the notification for a completed verification process.
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

}
