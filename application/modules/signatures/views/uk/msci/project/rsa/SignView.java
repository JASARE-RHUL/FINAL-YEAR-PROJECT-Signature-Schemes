package uk.msci.project.rsa;


import javafx.beans.value.ChangeListener;
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
import org.controlsfx.control.ToggleSwitch;

/**
 * The {@code SignView} class is responsible for managing the user interface related to the signing
 * process in the Signature Scheme POC application.
 */
public class SignView implements SignatureViewInterface {


  @FXML
  /**
   * Text Area for text to be signed.
   */
  private TextArea textInput;

  /**
   * The root pane of the signature view scene.
   */
  @FXML
  private AnchorPane root;

  /**
   * Horizontal Box containing the text input components.
   */
  @FXML
  private HBox textInputHBox;

  /**
   * Horizontal Box containing options for recovery actions.
   */
  @FXML
  private HBox recoveryOptions;

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
   * Button to trigger the export of the generated signature to a file.
   */
  @FXML
  private Button exportSignatureButton;

  /**
   * Button to trigger copying the generated signature to the clipboard.
   */
  @FXML
  private Button copySignatureButton;

  /**
   * Button to trigger the export of the non-recoverable message to a file.
   */
  @FXML
  private Button exportNonRecoverableMessageButton;

  /**
   * Button to trigger copying the non-recoverable message to the clipboard.
   */
  @FXML
  private Button copyNonRecoverableMessageButton;

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
   * Button for starting signature benchmarking.
   */
  @FXML
  private Button SigBenchmarkButton;

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
   * Initialises the SignView, setting up the toggle group for parameter choice.
   */
  public void initialize() {
    parameterChoiceToggleGroup = new ToggleGroup();
    standardParametersRadio.setToggleGroup(parameterChoiceToggleGroup);
    provablySecureParametersRadio.setToggleGroup(parameterChoiceToggleGroup);
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

  public String getTextInput() {
    return textInput.getText();
  }

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
  }

  /**
   * Sets the visibility of the HBox containing the text input components.
   *
   * @param visible true to make the HBox visible, false to hide it.
   */
  public void setTextInputHBoxVisibility(boolean visible) {
    this.textInputHBox.setVisible(visible);
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
   * @return A String representing the selected signature scheme.
   */
  public String getSelectedSignatureScheme() {
    return signatureSchemeDropdown.getValue();
  }

  /**
   * Sets the selected signature scheme in the signatureSchemeDropdown ComboBox.
   *
   * @param scheme A String representing the signature scheme to be selected.
   */
  public void setSelectedSignatureScheme(String scheme) {
    signatureSchemeDropdown.setValue(scheme);
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
   * Sets the visibility of the recoveryOptions HBox which contains recovery action options.
   *
   * @param visible true if the recovery options should be visible, false otherwise.
   */
  public void setRecoveryOptionsVisibility(boolean visible) {
    this.recoveryOptions.setVisible(visible);
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

  public void setMessageBatch(String text) {
    messageBatchField.setText(text);
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
   * Sets the visibility of the SigBenchmarkButton and manages its properties.
   *
   * @param visible true to make the SigBenchmarkButton visible, false to hide it.
   */
  public void setSigBenchmarkButtonVisibility(boolean visible) {
    SigBenchmarkButton.setVisible(visible);
    SigBenchmarkButton.setManaged(visible);
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
   * Registers an observer for the cancelImportTextButton Button's action event.
   * This observer is called when the user clicks the button to cancel the import of a text batch.
   *
   * @param observer The event handler to be registered.
   */
  public void addCancelImportTextButtonObserver(EventHandler<ActionEvent> observer) {
    cancelImportTextButton.setOnAction(observer);
  }

  /**
   * Registers an observer for the importKeyBatchButton Button's action event.
   * This observer is invoked when the user clicks the button to import a batch of keys.
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
   * Registers an observer for the SigBenchmarkButton Button's action event.
   *
   * @param observer The event handler to be registered.
   */
  public void addSigBenchmarkButtonObserver(EventHandler<ActionEvent> observer) {
    SigBenchmarkButton.setOnAction(observer);
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
   * Registers an observer for the exportSignatureButton Button's action event.
   *
   * @param observer The event handler to be registered.
   */
  void addExportSignatureObserver(EventHandler<ActionEvent> observer) {
    exportSignatureButton.setOnAction(observer);
  }

  /**
   * Registers an observer for the copySignatureButton Button's action event.
   *
   * @param observer The event handler to be registered.
   */
  void addCopySignatureObserver(EventHandler<ActionEvent> observer) {
    copySignatureButton.setOnAction(observer);
  }

  /**
   * Registers an observer for the exportNonRecoverableMessageButton Button's action event.
   *
   * @param observer The event handler to be registered.
   */
  void addExportNonRecoverableMessageObserver(EventHandler<ActionEvent> observer) {
    exportNonRecoverableMessageButton.setOnAction(observer);
  }

  /**
   * Registers observer for the copyNonRecoverableMessageButton Button's action event.
   *
   * @param observer The event handler to be registered.
   */
  void addCopyNonRecoverableMessageObserver(EventHandler<ActionEvent> observer) {
    copyNonRecoverableMessageButton.setOnAction(observer);
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


}
