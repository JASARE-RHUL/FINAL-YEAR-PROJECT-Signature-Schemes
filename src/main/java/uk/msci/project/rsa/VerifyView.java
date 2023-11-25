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

public class VerifyView implements SignatureViewInterface {
  @FXML
  private AnchorPane root;
  @FXML
  private Label falseLabel;
  @FXML
  private Label trueLabel;
  @FXML
  private Label textFileNameLabel;

  @FXML
  private HBox textInputHBox;
  @FXML
  private HBox sigFileHBox;
  @FXML
  private TextArea textInput;

  @FXML
  private VBox recoveryOptions;

  @FXML
  private ImageView textFileCheckmarkImage;
  @FXML
  private Button importTextButton;

  // Public Key Input and Import Button
  @FXML
  private TextField keyField;
  @FXML
  private ImageView checkmarkImage;
  @FXML
  private Button importKeyButton;

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
  @FXML
  private Button closeNotificationButton;


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
  public void setSigFileHBoxVisibility(boolean visible) {
    this.sigFileHBox.setVisible(visible);
  }
  public void setSigFileCheckmarkImageVisibility(boolean visible) {
    this.sigFileCheckmarkImage.setVisible(visible);
  }

  public void setTrueLabelVisibility(boolean visible) {
    this.trueLabel.setVisible(visible);
  }
  public void setFalseLabelVisibility(boolean visible) {
    this.falseLabel.setVisible(visible);
  }

  public ImageView getSigFileCheckmarkImage() {
    return sigFileCheckmarkImage;
  }

  // Setter for textFileCheckmarkImage
  public void setSigFileCheckmarkImage() {
    this.sigFileCheckmarkImage.setImage(new Image("/uk/msci/project/rsa/checkmark.png"));
    // Set the ImageView size
    this.sigFileCheckmarkImage.setFitWidth(20);
    this.sigFileCheckmarkImage.setFitHeight(20);
    // Preserve the image's aspect ratio
    this.sigFileCheckmarkImage.setPreserveRatio(true);
  }


  // Setter for textFileCheckmarkImage
  public void setTextFileCheckmarkImage(Image image) {
    this.textFileCheckmarkImage.setImage(image);
  }


  public void setCheckmarkImage(Image image) {
    this.checkmarkImage.setImage(image);
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

  public String getSigText() {
    return signatureText.getText();
  }

  public void setSignatureText(String text) {
    this.signatureText.setText(text);
  }

  public void setSignatureTextVisibility(boolean visible) {
    this.signatureText.setVisible(visible);
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


  public void setRecoveryOptionsVisibility(boolean visible) {
    this.recoveryOptions.setVisible(visible);
  }

  public StackPane getNotificationPane() {
    return notificationPane;
  }


  public void addImportTextObserver(EventHandler<ActionEvent> observer) {
    importTextButton.setOnAction(observer);
  }

  void addVerifyBtnObserver(EventHandler<ActionEvent> observer) {
    verifyBtn.setOnAction(observer);
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


  void addExportRecoverableMessageObserver(EventHandler<ActionEvent> observer) {
    exportRecoverableMessageButton.setOnAction(observer);
  }

  void addCopyRecoverableMessageObserver(EventHandler<ActionEvent> observer) {
    copyRecoverableMessageButton.setOnAction(observer);
  }

  public void addCloseNotificationObserver(EventHandler<ActionEvent> observer) {
    closeNotificationButton.setOnAction(observer);
  }

  void addImportSigButtonObserver(EventHandler<ActionEvent> observer) {
    importSigButton.setOnAction(observer);
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



}
