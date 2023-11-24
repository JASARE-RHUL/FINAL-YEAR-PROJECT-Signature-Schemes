package uk.msci.project.rsa;


import javafx.beans.value.ChangeListener;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.layout.StackPane;


public class SignView {

  // Text Area and Import Text Button
  @FXML
  private TextArea textToSign;
  @FXML
  private Label textFileNameLabel;
  @FXML
  private ImageView textFileCheckmarkImage;
  @FXML
  private Button importTextButton;

  // Private Key Input and Import Button
  @FXML
  private TextField privateKeyField;
  @FXML
  private ImageView checkmarkImage;
  @FXML
  private Button importPrivateKeyButton;

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
  private Button exportSignatureButton; // Assuming you want to access these buttons
  @FXML
  private Button copySignatureButton;
  @FXML
  private Button exportNonRecoverableMessageButton;
  @FXML
  private Button copyNonRecoverableMessageButton;
  @FXML
  private Button closeNotificationButton;
  // Other fields...

  // Getters and setters

  // Getter for textFileCheckmarkImage
  public ImageView getTextFileCheckmarkImage() {
    return textFileCheckmarkImage;
  }

  // Setter for textFileCheckmarkImage
  public void setTextFileCheckmarkImage(Image image) {
    this.textFileCheckmarkImage.setImage(image);
  }

  public ImageView getCheckmarkImage() {
    return checkmarkImage;
  }

  public void setCheckmarkImage(Image image) {
    this.checkmarkImage.setImage(image);
  }

  public String getTextToSign() {
    return textToSign.getText();
  }

  public void setTextToSign(String text) {
    this.textToSign.setText(text);
  }

  public String getPrivateKey() {
    return privateKeyField.getText();
  }

  public void setPrivateKey(String key) {
    this.privateKeyField.setText(key);
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

  void addImportTextObserver(EventHandler<ActionEvent> observer) {
    importTextButton.setOnAction(observer);
  }

  void addCreateSignatureObserver(EventHandler<ActionEvent> observer) {
    createSignatureButton.setOnAction(observer);
  }

  void addMenuButtonObserver(EventHandler<ActionEvent> observer) {
    backToMainMenuButton.setOnAction(observer);
  }

  void addHelpObserver(EventHandler<ActionEvent> observer) {
    helpButton.setOnAction(observer);
  }

  void addImportKeyObserver(EventHandler<ActionEvent> observer) {
    importPrivateKeyButton.setOnAction(observer);
  }

  void addSignatureSchemeChangeObserver(ChangeListener<String> observer) {
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

  void addCloseNotificationObserver(EventHandler<ActionEvent> observer) {
    closeNotificationButton.setOnAction(observer);
  }

}
