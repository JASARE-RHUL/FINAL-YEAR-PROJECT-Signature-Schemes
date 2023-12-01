package uk.msci.project.rsa;

import javafx.beans.value.ChangeListener;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.scene.Node;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;

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
   * Registers an oberver for the import key button click action.
   *
   * @param observer The event handler to register.
   */
  public void addImportKeyObserver(EventHandler<ActionEvent> observer) {
    importKeyButton.setOnAction(observer);
  }

  /**
   * Registers an observer for the signature scheme dropdown value changes.
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
