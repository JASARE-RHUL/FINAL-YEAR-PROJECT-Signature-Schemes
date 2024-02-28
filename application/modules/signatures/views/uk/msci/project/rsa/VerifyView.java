package uk.msci.project.rsa;

import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;

/**
 * The {@code VerifyView} class is responsible for managing the user interface related to the
 * verification process in the Signature Scheme application.
 */
public class VerifyView extends SignatureBaseView {

  @FXML
  private HBox sigFileHBox;   // Container for the signature input area and file name label

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

  // Button to initiate the verification of the signature
  @FXML
  private Button verifyBtn;

  @FXML
  private Button cancelImportSignatureButton;

  @FXML
  private Label signatureBatchText;

  @FXML
  private TextField signatureField;

  @FXML
  private Button verificationBenchmarkButton;

  @FXML
  private Button importSigBatchButton;

  @FXML
  private Button cancelImportSigBatchButton;

  @FXML
  private HBox signatureBatchHBox;

  // Buttons within the notification pane for actions related to the recoverable message
  @FXML
  private Button exportRecoverableMessageButton;
  @FXML
  private Button copyRecoverableMessageButton;

  // Labels for indicating the result of the signature verification
  @FXML
  private Label falseLabel; // Indicates a failed verification
  @FXML
  private Label trueLabel;  // Indicates a successful verification

  // VBox container for recovery options, shown after verification
  @FXML
  private VBox recoveryOptions;

  /**
   * Sets the visibility of the HBox that contains the signature file information.
   *
   * @param visible true to show the HBox, false to hide it.
   */
  public void setSigFileHBoxVisibility(boolean visible) {
    this.sigFileHBox.setManaged(visible);
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
    this.signatureText.setManaged(visible);
    this.signatureText.setVisible(visible);
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


  public void setImportSigButtonVisibility(boolean visible) {
    importSigButton.setManaged(visible);
    importSigButton.setVisible(visible);
  }

  /**
   * Sets the visibility of the cancelImportSignatureButton and manages its properties.
   *
   * @param visible true to make the cancelImportSignatureButton visible, false to hide it.
   */
  public void setCancelImportSignatureButtonVisibility(boolean visible) {
    cancelImportSignatureButton.setVisible(visible);
    cancelImportSignatureButton.setManaged(visible);
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
   * Registers an observer for the verify button click action.
   *
   * @param observer The event handler to register.
   */
  void addVerifyBtnObserver(EventHandler<ActionEvent> observer) {
    verifyBtn.setOnAction(observer);
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
   * Registers an observer for the cancelImportSignatureButton Button's action event. This observer
   * is called when the user clicks the button to cancel the import of a text batch.
   *
   * @param observer The event handler to be registered.
   */
  public void addCancelImportSignatureButtonObserver(EventHandler<ActionEvent> observer) {
    cancelImportSignatureButton.setOnAction(observer);
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
   * Registers an observer for the cancelImportSignatureButton Button's action event. This observer
   * is called when the user clicks the button to cancel the import of a text batch in standard
   * mode.
   *
   * @param observer The event handler to be registered.
   */
  public void addCancelImportSignatureBatchButtonObserver(EventHandler<ActionEvent> observer) {
    cancelImportSignatureButton.setOnAction(observer);
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
   * Sets the visibility of the recoveryOptions VBox which contains recovery action options.
   *
   * @param visible true if the recovery options should be visible, false otherwise.
   */
  public void setRecoveryOptionsVisibility(boolean visible) {
    this.recoveryOptions.setVisible(visible);
  }


}
