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


public class SignView implements SignatureViewInterface {

  // Text Area and Import Text Button
  @FXML
  private TextArea textInput;

  @FXML
  private AnchorPane root;

  @FXML
  private HBox textInputHBox;

  @FXML
  private HBox recoveryOptions;
  @FXML
  private Label textFileNameLabel;
  @FXML
  private ImageView textFileCheckmarkImage;
  @FXML
  private Button importTextButton;

  // Private Key Input and Import Button
  @FXML
  private TextField keyField;
  @FXML
  private ImageView checkmarkImage;
  @FXML
  private Button importKeyButton;

  // Signature Scheme Dropdown
  @FXML
  private ComboBox<String> signatureSchemeDropdown;

  // Create Signature Button
  @FXML
  private Button createSignatureButton;

  // Navigation Buttons
  @FXML
  private Button backToMainMenuButton;
  @FXML
  private Button helpButton;

  // Overlay Notification Pane and its components
  @FXML
  private StackPane notificationPane;

  @FXML
  private Button exportSignatureButton;
  @FXML
  private Button copySignatureButton;
  @FXML
  private Button exportNonRecoverableMessageButton;
  @FXML
  private Button copyNonRecoverableMessageButton;
  @FXML
  private Button closeNotificationButton;

  // Getters and setters

  // Getter for textFileCheckmarkImage
  public ImageView getTextFileCheckmarkImage() {
    return textFileCheckmarkImage;
  }

  // Setter for textFileCheckmarkImage
  public void setTextFileCheckmarkImage() {
    this.textFileCheckmarkImage.setImage(new Image("/uk/msci/project/rsa/checkmark.png"));

    // Set the ImageView size
    this.textFileCheckmarkImage.setFitWidth(20);
    this.textFileCheckmarkImage.setFitHeight(20);

    // Preserve the image's aspect ratio
    this.textFileCheckmarkImage.setPreserveRatio(true);
  }

  public ImageView getCheckmarkImage() {
    return checkmarkImage;
  }

  public void setCheckmarkImage() {
    this.checkmarkImage.setImage(new Image("/uk/msci/project/rsa/checkmark.png"));
    // Set the ImageView size
    this.checkmarkImage.setFitWidth(20);
    this.checkmarkImage.setFitHeight(20);
    // Preserve the image's aspect ratio
    this.checkmarkImage.setPreserveRatio(true);
  }

  public void setCheckmarkImageVisibility(boolean visible) {
    this.checkmarkImage.setVisible(visible);
  }

  public void setNotificationPaneVisible(boolean visible) {
    this.notificationPane.setVisible(visible);
  }

  public String getTextInput() {
    return textInput.getText();
  }

  public void setTextInput(String text) {
    this.textInput.setText(text);
  }

  public void setTextInputVisibility(boolean visible) {
    this.textInput.setVisible(visible);
  }

  public void setTextInputHBoxVisibility(boolean visible) {
    this.textInputHBox.setVisible(visible);
  }

  public String getKey() {
    return keyField.getText();
  }

  public void setKey(String key) {
    this.keyField.setText(key);
  }

  public void setKeyVisibility(boolean visible) {
    this.keyField.setVisible(visible);
  }

  public String getSelectedSignatureScheme() {
    return signatureSchemeDropdown.getValue();
  }

  public void setSelectedSignatureScheme(String scheme) {
    signatureSchemeDropdown.setValue(scheme);
  }

  public String getTextFileNameLabel() {
    return textFileNameLabel.getText();
  }

  public void setTextFileNameLabel(String fileName) {
    this.textFileNameLabel.setText(fileName);
  }

  public void setImportTextButtonLabel(String label) {
    this.importTextButton.setText(label);
  }

  public String getImportTextButtonLabel() {
    return this.importTextButton.getText();
  }

  public StackPane getNotificationPane() {
    return notificationPane;
  }

  public void setRecoveryOptionsVisibility(boolean visible) {
    this.recoveryOptions.setVisible(visible);
  }

  public void addImportTextObserver(EventHandler<ActionEvent> observer) {
    importTextButton.setOnAction(observer);
  }

  void addCreateSignatureObserver(EventHandler<ActionEvent> observer) {
    createSignatureButton.setOnAction(observer);
  }

  public void addBackToMainMenuObserver(EventHandler<ActionEvent> observer) {
    backToMainMenuButton.setOnAction(observer);
  }

  public void addHelpObserver(EventHandler<ActionEvent> observer) {
    helpButton.setOnAction(observer);
  }

  public void addImportKeyObserver(EventHandler<ActionEvent> observer) {
    importKeyButton.setOnAction(observer);
  }

  public void addSignatureSchemeChangeObserver(ChangeListener<String> observer) {
    signatureSchemeDropdown.valueProperty().addListener(observer);
  }

  void addExportSignatureObserver(EventHandler<ActionEvent> observer) {
    exportSignatureButton.setOnAction(observer);
  }

  void addCopySignatureObserver(EventHandler<ActionEvent> observer) {
    copySignatureButton.setOnAction(observer);
  }

  void addExportNonRecoverableMessageObserver(EventHandler<ActionEvent> observer) {
    exportNonRecoverableMessageButton.setOnAction(observer);
  }

  void addCopyNonRecoverableMessageObserver(EventHandler<ActionEvent> observer) {
    copyNonRecoverableMessageButton.setOnAction(observer);
  }

  public void addCloseNotificationObserver(EventHandler<ActionEvent> observer) {
    closeNotificationButton.setOnAction(observer);
  }

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

   public void closeNotificationPane() {
    notificationPane.setVisible(false);
    notificationPane.setDisable(true);
    keyField.setText("");
    textInput.setText("");

    signatureSchemeDropdown.setValue(null); // Or set to your default value

    textFileCheckmarkImage.setImage(null);

    // Re-enable all sibling nodes of notificationPane
    for (Node child : root.getChildren()) {
      child.setDisable(false);
    }
  }


}
