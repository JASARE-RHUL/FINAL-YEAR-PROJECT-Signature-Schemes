package uk.msci.project.rsa;

import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.scene.control.Button;

public class MainMenuView {
  @FXML private Button generateKeysButton;
  @FXML private Button signDocumentButton;
  @FXML private Button verifySignatureButton;
  @FXML private Button helpButton;

  // Add Event Handler Methods
  void addGenerateKeysObserver(EventHandler<ActionEvent> observer) {
    generateKeysButton.setOnAction(observer);
  }

  void addSignDocumentObserver(EventHandler<ActionEvent> observer) {
    signDocumentButton.setOnAction(observer);
  }

  void addVerifySignatureObserver(EventHandler<ActionEvent> observer) {
    verifySignatureButton.setOnAction(observer);
  }

  void addHelpObserver(EventHandler<ActionEvent> observer) {
    helpButton.setOnAction(observer);
  }

}
