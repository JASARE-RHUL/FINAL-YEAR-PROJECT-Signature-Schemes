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

  /**
   * A utility class that provides static methods for common display operations such as showing
   * alerts, copying text to clipboard, and handling file imports within the application.
   */
  public static class DisplayUtility {

    /**
     * Handles the file import operation used by both text and key import functionalities. It prompts
     * the user to choose a file and then applies the provided fileConsumer to the selected file.
     *
     * @param stage        The stage used to show the file chooser dialog.
     * @param extension    The file extension filter description used in the file chooser.
     * @param fileConsumer The consumer that will handle the chosen file.
     */
    protected static void handleFileImport(Stage stage, String extension,
        Consumer<File> fileConsumer) {
      FileChooser fileChooser = new FileChooser();
      fileChooser.setTitle("Open Resource File");
      FileChooser.ExtensionFilter extFilter = new FileChooser.ExtensionFilter(
          extension.toUpperCase() + " files", extension);
      fileChooser.getExtensionFilters().add(extFilter);
      File file = fileChooser.showOpenDialog(stage);
      if (file != null) {
        fileConsumer.accept(file);
      }
    }

    /**
     * Copies the provided text to the system clipboard and displays an alert.
     *
     * @param text  The text to be copied to the clipboard.
     * @param asset The name of the asset to be displayed in the confirmation alert.
     */
    protected static void copyToClipboard(String text, String asset) {
      Clipboard clipboard = Clipboard.getSystemClipboard();
      ClipboardContent content = new ClipboardContent();
      content.putString(text);
      clipboard.setContent(content);
      showInfoAlert("Clipboard", asset + " was successfully copied to clipboard!");
    }


    /**
     * Shows an alert of the given type, with the specified title and content.
     *
     * @param type    The type of alert to show.
     * @param title   The title of the alert dialog.
     * @param content The content text to display in the alert dialog.
     */
    protected static void showAlert(AlertType type, String title, String content) {
      Alert alert = new Alert(type);
      alert.setTitle(title);
      alert.setHeaderText(null);
      alert.setContentText(content);
      alert.showAndWait();
    }

    /**
     * Shows a customised error alert specified content.
     *
     * @param content The content text to error in the alert dialog.
     */
    protected static void showErrorAlert(String content) {
      showAlert(AlertType.ERROR, "Error", content);
    }

    /**
     * Displays an informational alert with the given title and content.
     *
     * @param title   The title for the informational alert.
     * @param content The message to display in the informational alert.
     */
    protected static void showInfoAlert(String title, String content) {
      showAlert(AlertType.INFORMATION, title, content);
    }

  }
}
