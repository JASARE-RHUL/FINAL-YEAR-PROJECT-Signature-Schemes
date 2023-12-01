package uk.msci.project.rsa;

import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.image.ImageView;
import javafx.scene.layout.VBox;

/**
 * The domain object corresponding to GenView FXML file that will serve as a controllers interface
 * into observing and manipulating the graphical layout of the view.
 */
public class GenView {

  /**
   * ImageView that possibly contains a logo or relevant image for the application.
   */
  @FXML
  private ImageView logoImageView;

  /**
   * TextField for the user to enter the desired key sizes, separated by commas.
   */
  @FXML
  private TextField keySizeTextField;

  /**
   * Button that triggers the generation of keys when clicked.
   */
  @FXML
  private Button generateButton;

  /**
   * VBox that contains elements to be shown when key generation is successful.
   */
  @FXML
  private VBox successPopup;

  /**
   * VBox that contains elements to be displayed when key generation fails.
   */
  @FXML
  private VBox failurePopup;

  /**
   * Label to display failure messages.
   */
  @FXML
  private Label failureLabel;

  /**
   * Button to export the generated private key.
   */
  @FXML
  private Button exportPrivateKeyButton;

  /**
   * Button to export the generated public key.
   */
  @FXML
  private Button exportPublicKeyButton;

  /**
   * Button to navigate back to the main menu.
   */
  @FXML
  private Button backToMainMenuButton;

  /**
   * Button that provides help information when clicked.
   */
  @FXML
  private Button helpButton;

  /**
   * Gets the ImageView that may contain a logo.
   *
   * @return ImageView the ImageView component.
   */
  public ImageView getLogoImageView() {
    return logoImageView;
  }

  /**
   * Sets the logo image view.
   *
   * @param logoImageView The ImageView to set.
   */
  public void setLogoImageView(ImageView logoImageView) {
    this.logoImageView = logoImageView;
  }

  /**
   * Retrieves the key size specified in the TextField.
   *
   * @return String the key size text.
   */
  public String getKeySize() {
    return keySizeTextField.getText();
  }

  /**
   * Sets the key size in the TextField.
   *
   * @param keySize A string representing the key size.
   */
  public void setKeySize(String keySize) {
    this.keySizeTextField.setText(keySize);
  }

  /**
   * Sets the failure message label text.
   *
   * @param label The failure message to display.
   */
  public void setFailureLabel(String label) {
    this.failureLabel.setText(label);
  }

  /**
   * Gets the VBox that is shown on successful key generation.
   *
   * @return VBox the success popup component.
   */
  public VBox getSuccessPopup() {
    return successPopup;
  }

  /**
   * Sets the visibility of the success popup.
   *
   * @param visible A boolean to set the popup's visibility.
   */
  public void setSuccessPopupVisible(boolean visible) {
    this.successPopup.setVisible(visible);
  }

  /**
   * Sets the visibility of the failure popup.
   *
   * @param visible A boolean to set the popup's visibility.
   */
  public void setFailurePopupVisible(boolean visible) {
    this.failurePopup.setVisible(visible);
  }

  /**
   * Registers an observer for the generate button action event.
   *
   * @param observer The event handler to observe the action.
   */
  void addGenerateButtonObserver(EventHandler<ActionEvent> observer) {
    generateButton.setOnAction(observer);
  }

  /**
   * Registers an observer for the export private key button action event.
   *
   * @param observer The event handler to observe the action.
   */
  void addExportPrivateKeyObserver(EventHandler<ActionEvent> observer) {
    exportPrivateKeyButton.setOnAction(observer);
  }

  /**
   * Registers an observer for the export public key button action event.
   *
   * @param observer The event handler to observe the action.
   */
  void addExportPublicKeyObserver(EventHandler<ActionEvent> observer) {
    exportPublicKeyButton.setOnAction(observer);
  }

  /**
   * Registers an observer for the back to main menu button action event.
   *
   * @param observer The event handler to observe the action.
   */
  void addBackToMainMenuObserver(EventHandler<ActionEvent> observer) {
    backToMainMenuButton.setOnAction(observer);
  }

  /**
   * Registers an observer for the help button action event.
   *
   * @param observer The event handler to observe the action.
   */
  void addHelpObserver(EventHandler<ActionEvent> observer) {
    helpButton.setOnAction(observer);
  }


}
