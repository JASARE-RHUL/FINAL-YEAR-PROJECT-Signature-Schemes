package uk.msci.project.rsa;

import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.image.ImageView;
import javafx.scene.layout.VBox;

public class GenView {
  @FXML private ImageView logoImageView;
  @FXML private TextField keySizeTextField;
  @FXML private Button generateButton;
  @FXML private VBox successPopup;
  @FXML private Button exportPrivateKeyButton;
  @FXML private Button exportPublicKeyButton;
  @FXML private Button backToMainMenuButton;
  @FXML private Button helpButton;

  // Getters and Setters
  public ImageView getLogoImageView() {
    return logoImageView;
  }

  public void setLogoImageView(ImageView logoImageView) {
    this.logoImageView = logoImageView;
  }

  public String getKeySize() {
    return keySizeTextField.getText();
  }

  public void setKeySize(String keySize) {
    this.keySizeTextField.setText(keySize);
  }

  public VBox getSuccessPopup() {
    return successPopup;
  }

  public boolean isSuccessPopupVisible() {
    return successPopup.isVisible();
  }

  public void setSuccessPopupVisible(boolean visible) {
    this.successPopup.setVisible(visible);
  }

  // Event Handlers
  void addGenerateButtonObserver(EventHandler<ActionEvent> observer) {
    generateButton.setOnAction(observer);
  }

  void addExportPrivateKeyObserver(EventHandler<ActionEvent> observer) {
    exportPrivateKeyButton.setOnAction(observer);
  }

  void addExportPublicKeyObserver(EventHandler<ActionEvent> observer) {
    exportPublicKeyButton.setOnAction(observer);
  }

  void addBackToMainMenuObserver(EventHandler<ActionEvent> observer) {
    backToMainMenuButton.setOnAction(observer);
  }

  void addHelpObserver(EventHandler<ActionEvent> observer) {
    helpButton.setOnAction(observer);
  }

}
