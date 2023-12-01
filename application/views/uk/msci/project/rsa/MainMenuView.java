package uk.msci.project.rsa;

import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.scene.control.Button;

/**
 * The {@code MainMenuView} class is responsible for managing the user interface related to the
 * navigation portal of the Signature Scheme POC application. Serves as a portal in to specific
 * functionality such as key generation or creating signatures.
 */
public class MainMenuView {

  /**
   * Button for navigating to the key generation functionality.
   */
  @FXML
  private Button generateKeysButton;

  /**
   * Button for navigating to the document signing functionality.
   */
  @FXML
  private Button signDocumentButton;

  /**
   * Button for accessing the signature verification feature.
   */
  @FXML
  private Button verifySignatureButton;

  /**
   * Button for accessing help resources and additional information.
   */
  @FXML
  private Button helpButton;


  /**
   * Registers an observer for the 'Generate Keys' button action.
   *
   * @param observer The event handler to be invoked when the 'Generate Keys' button is clicked.
   */
  void addGenerateKeysObserver(EventHandler<ActionEvent> observer) {
    generateKeysButton.setOnAction(observer);
  }

  /**
   * Registers an observer for the 'Sign Document' button action.
   *
   * @param observer The event handler to be invoked when the 'Sign Document' button is clicked.
   */
  void addSignDocumentObserver(EventHandler<ActionEvent> observer) {
    signDocumentButton.setOnAction(observer);
  }

  /**
   * Registers an observer for the 'Verify Signature' button action.
   *
   * @param observer The event handler to be invoked when the 'Verify Signature' button is clicked.
   */
  void addVerifySignatureObserver(EventHandler<ActionEvent> observer) {
    verifySignatureButton.setOnAction(observer);
  }

  /**
   * Registers an observer for the 'Help' button action.
   *
   * @param observer The event handler to be invoked when the 'Help' button is clicked.
   */
  void addHelpObserver(EventHandler<ActionEvent> observer) {
    helpButton.setOnAction(observer);
  }

}
