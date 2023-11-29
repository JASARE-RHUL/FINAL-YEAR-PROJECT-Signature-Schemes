package uk.msci.project.rsa;

import java.io.File;
import java.util.function.Consumer;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;
import javafx.scene.control.Button;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

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
