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
import javafx.scene.layout.VBox;

public class VerifyView {

  // Text Area and Import Text Button

  @FXML
  private Label textFileNameLabel;

  @FXML
  private TextArea textToVerify;

  @FXML
  private ImageView textFileCheckmarkImage;
  @FXML
  private Button importTextButton;

  // Public Key Input and Import Button
  @FXML
  private TextField publicKeyField;
  @FXML
  private ImageView checkmarkImage;
  @FXML
  private Button importPublicKeyButton;

  // Signature TextArea and Import Signature Button
  @FXML
  private TextArea signatureText;
  @FXML
  private Label sigFileNameLabel;
  @FXML
  private ImageView sigFileCheckmarkImage;
  @FXML
  private Button importSigButton;

  // Signature Scheme Dropdown
  @FXML
  private ComboBox<String> signatureSchemeDropdown;

  // Verify Signature Button
  @FXML
  private Button verifyBtn;

  // Navigation Buttons
  @FXML
  private Button backToMainMenuButton;
  @FXML
  private Button helpButton;


  // Overlay Notification Pane and its components
  @FXML
  private StackPane notificationPane;
  @FXML
  private Button exportRecoverableMessageButton;
  @FXML
  private Button copyRecoverableMessageButton;

  // Getters and setters
  // (Add getters and setters for all the components as required)

  // Getters and setters

  // Getter for textFileCheckmarkImage
  public ImageView getSigFileCheckmarkImage() {
    return sigFileCheckmarkImage;
  }

  // Setter for textFileCheckmarkImage
  public void setSigFileCheckmarkImage(Image image) {
    this.sigFileCheckmarkImage.setImage(image);
  }

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

  public String getTextToVerify() {
    return textToVerify.getText();
  }

  public void setTextToVerify(String text) {
    this.textToVerify.setText(text);
  }

  public String getSigText() {
    return signatureText.getText();
  }

  public void setSignatureText(String text) {
    this.signatureText.setText(text);
  }

  public String getPublicKey() {
    return publicKeyField.getText();
  }

  public void setPublicKey(String key) {
    this.publicKeyField.setText(key);
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

  public String getSigFileNameLabel() {
    return sigFileNameLabel.getText();
  }

  public void setSigFileNameLabel(String fileName) {
    this.sigFileNameLabel.setText(fileName);
  }

  public String getImportTextButtonLabel() {
    return this.importTextButton.getText();
  }

  public void setImportTextButtonLabel(String label) {
    this.importTextButton.setText(label);
  }

  public String getImportSigButtonLabel() {
    return this.importSigButton.getText();
  }

  public void setImportSigButtonLabel(String label) {
    this.importSigButton.setText(label);
  }


  public StackPane getNotificationPane() {
    return notificationPane;
  }


  void addImportTextObserver(EventHandler<ActionEvent> observer) {
    importTextButton.setOnAction(observer);
  }

  void addVerifyBtnObserver(EventHandler<ActionEvent> observer) {
    verifyBtn.setOnAction(observer);
  }

  void addMenuButtonObserver(EventHandler<ActionEvent> observer) {
    backToMainMenuButton.setOnAction(observer);
  }

  void addHelpObserver(EventHandler<ActionEvent> observer) {
    helpButton.setOnAction(observer);
  }

  void addImportKeyObserver(EventHandler<ActionEvent> observer) {
    importPublicKeyButton.setOnAction(observer);
  }

  void addSignatureSchemeChangeObserver(ChangeListener<String> observer) {
    signatureSchemeDropdown.valueProperty().addListener(observer);
  }


  void addExportRecoverableMessageObserver(EventHandler<ActionEvent> observer) {
    exportRecoverableMessageButton.setOnAction(observer);
  }

  void addCopyRecoverableMessageObserver(EventHandler<ActionEvent> observer) {
    copyRecoverableMessageButton.setOnAction(observer);
  }

  void addImportSigButtonObserver(EventHandler<ActionEvent> observer) {
    importSigButton.setOnAction(observer);
  }



}
