package uk.msci.project.rsa;

import java.io.File;
import java.math.BigInteger;
import java.util.function.Consumer;
import java.util.regex.Pattern;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;
import java.io.IOException;


/**
 * This class is part of the controller component specific to digital signature operations
 * responsible for handling user interactions for the signature process. It also communicates with
 * the Signature Model to perform the actual signature processing logic.
 */
public class SignatureController {

  /**
   * The view component of the MVC pattern for the signing functionality. It handles the user
   * interface for the digital signature generation.
   */
  private SignView signView;

  /**
   * The view component of the MVC pattern for the verification functionality. It handles the user
   * interface for the digital signature verification.
   */
  private VerifyView verifyView;

  /**
   * The model component of the MVC pattern that handles the data and business logic for digital
   * signature creation and verification.
   */
  private SignatureModel signatureModel;

  /**
   * The main controller that orchestrates the flow between different views of the application.
   */
  private MainController mainController;

  /**
   * The message to be signed or verified, stored as a byte array.
   */
  private byte[] message;

  /**
   * The digital signature generated after signing the message. It is stored as a String for storage
   * purposes.
   */
  private String signature;

  /**
   * Constructs a SignatureController with a reference to the MainController to be used in the event
   * of the user initiating a switch back to main menu.
   *
   * @param mainController The main controller that this controller is part of.
   */
  public SignatureController(MainController mainController) {
    this.mainController = mainController;
  }

  /**
   * Initialises and displays the SignView stage. It loads the FXML for the SignView and sets up the
   * scene and the stage.
   *
   * @param primaryStage The primary stage for this application.
   */
  public void showSignView(Stage primaryStage) {
    try {
      FXMLLoader loader = new FXMLLoader(getClass().getResource("SignView.fxml"));
      Parent root = loader.load();
      signView = loader.getController();
      signatureModel = new SignatureModel();

      // Set up observers for SignView
      setupObservers(primaryStage);

      primaryStage.setScene(new Scene(root));
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  /**
   * Sets up observers for the SignView controls. Observers are added to handle events like text
   * import, key import, and signature scheme changes.
   *
   * @param primaryStage The stage that observers will use for file dialogs.
   */
  private void setupObservers(Stage primaryStage) {
    signView.addImportTextObserver(new ImportTextObserver(primaryStage, this::handleMessageFile));
    signView.addImportKeyObserver(new ImportKeyObserver(primaryStage, this::handlePrivateKey));
    signView.addSignatureSchemeChangeObserver(new SignatureSchemeChangeObserver());
    signView.addCreateSignatureObserver(new CreateSignatureObserver());
    signView.addBackToMainMenuObserver(new BackToMainMenuObserver());
    signView.addCopySignatureObserver(new CopySignatureObserver());
    signView.addExportSignatureObserver(new ExportSignatureObserver());
    signView.addExportNonRecoverableMessageObserver(new ExportNonRecoverableMessageObserver());
    signView.addCopyNonRecoverableMessageObserver(new CopyNonRecoverableMessageObserver());
    signView.addCloseNotificationObserver(new BackToMainMenuObserver());
  }


  /**
   * Handles the importing of a private key file. Validates the key and updates the model and view
   * accordingly.
   *
   * @param file The private key file selected by the user.
   */
  public void handlePrivateKey(File file) {
    String content = "";
    try {
      content = FileHandle.importFromFile(file);
    } catch (Exception e) {
      DisplayUtility.showErrorAlert("Error importing file, please try again.");
    }
    if (!(Pattern.compile("^\\d+(,\\d+)*$").matcher(content).matches())) {
      DisplayUtility.showErrorAlert("Error, Invalid Key.");
    } else {
      signatureModel.setKey(new PublicKey(content));
      signView.setCheckmarkImage();
      signView.setCheckmarkImageVisibility(true);
      signView.setPrivateKey(file.getName());
      signView.setPrivateKeyVisibility(true);
    }
  }

  /**
   * Observer responsible for handling the import of a private key file. It utilises a file chooser
   * to select a key file and then processes it using a provided Consumer.
   */
  class ImportKeyObserver implements EventHandler<ActionEvent> {

    private Stage stage;
    private Consumer<File> fileConsumer;

    /**
     * Constructs an observer for importing a private key file.
     *
     * @param stage        The primary stage of the application to show the file chooser.
     * @param fileConsumer A consumer to process the selected private key file.
     */
    public ImportKeyObserver(Stage stage, Consumer<File> fileConsumer) {
      this.stage = stage;
      this.fileConsumer = fileConsumer;
    }

    @Override
    public void handle(ActionEvent event) {
      DisplayUtility.handleFileImport(stage, "*.rsa", fileConsumer);
    }
  }

  /**
   * Handles the file selected by the user for the message to be signed. Reads the file contents and
   * updates the view to reflect the text has been loaded. If the file content does not meet the
   * expected format, an error alert is shown.
   *
   * @param file The file selected by the user containing the message to sign.
   */
  public void handleMessageFile(File file) {
    String content = "";
    try {
      content = FileHandle.importFromFile(file);
    } catch (Exception e) {
      DisplayUtility.showErrorAlert("Error importing file, please try again.");
    }
    if (content == "") {
      DisplayUtility.showErrorAlert(file.getName() + " is empty. Please try again.");
    } else {
      message = content.getBytes();
      signView.setTextToSign("");
      signView.setTextFileNameLabel(file.getName());
      signView.setTextToSignVisibility(false);
      signView.setTextFileCheckmarkImage();
      signView.setTextToSignHBoxVisibility(true);
    }
  }

  /**
   * The observer for importing text files. This class handles the action event triggered when the
   * user wants to import text to be signed.
   */
  class ImportTextObserver implements EventHandler<ActionEvent> {

    private Stage stage;
    private Consumer<File> fileConsumer;

    /**
     * Constructs an ImportTextObserver with a stage and a file consumer.
     *
     * @param stage        The stage to be used for showing file dialogs.
     * @param fileConsumer The consumer that will process the selected file.
     */
    public ImportTextObserver(Stage stage, Consumer<File> fileConsumer) {
      this.stage = stage;
      this.fileConsumer = fileConsumer;
    }

    @Override
    public void handle(ActionEvent event) {
      DisplayUtility.handleFileImport(stage, "*.txt", fileConsumer);
    }
  }

  /**
   * The observer for changes in signature scheme selection. This class reacts to changes in the
   * selected signature scheme and updates the model accordingly.
   */
  class SignatureSchemeChangeObserver implements ChangeListener<String> {

    /**
     * Responds to changes in the selected signature scheme.
     *
     * @param observable The observable value.
     * @param oldValue   The previous value.
     * @param newValue   The new value.
     */
    @Override
    public void changed(ObservableValue<? extends String> observable, String oldValue,
        String newValue) {
      switch (newValue) {
        case "ANSI X9.31 rDSA":
          signatureModel.setSignatureType(SignatureType.ANSI_X9_31_RDSA);
          break;
        case "ISO\\IEC 9796-2 Scheme 1":
          signatureModel.setSignatureType(SignatureType.ISO_IEC_9796_2_SCHEME_1);
          break;
        case "PKCS#1 v1.5":
        default:
          signatureModel.setSignatureType(SignatureType.RSASSA_PKCS1_v1_5);
      }
    }
  }

  /**
   * The observer for creating signatures. This class handles the action event triggered for the
   * signature generation process.
   */
  class CreateSignatureObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
      if ((signView.getTextToSign().equals("") && message == null)
          || signatureModel.getKey() == null
          || signView.getSelectedSignatureScheme() == null) {
        DisplayUtility.showErrorAlert(
            "You must provide an input for all fields. Please try again.");
        return;
      }
      try {
        String textToSign = signView.getTextToSign();
        if (!textToSign.equals("")) {
          message = textToSign.getBytes();
        }
        signatureModel.instantiateSignatureScheme();
        signature = new BigInteger(1, signatureModel.sign(message)).toString();

        if (signatureModel.getNonRecoverableM() != null) {
          signView.setRecoveryOptionsVisibility(true);
        }
        signView.showNotificationPane();
      } catch (Exception e) {
        DisplayUtility.showErrorAlert(
            "There was an error generating a signature. Please try again.");
        e.printStackTrace();

      }
    }
  }

  /**
   * The observer for copying the signature to the clipboard. This class handles the action event
   * triggered when the user wants to copy the generated signature to the clipboard.
   */
  class CopySignatureObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
      try {
        DisplayUtility.copyToClipboard(signature, "Signature");
      } catch (Exception e) {
        DisplayUtility.showErrorAlert("Failed to copy signature to clipboard.");
      }
    }
  }

  /**
   * The observer for exporting the signature to a file. This class handles the action event
   * triggered when the user wants to export the generated signature to a file.
   */
  class ExportSignatureObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
      try {
        FileHandle.exportToFile("signature.rsa", signature);
        DisplayUtility.showInfoAlert("Export", "Signature was successfully exported!");
      } catch (Exception e) {
        e.printStackTrace();
      }
    }
  }

  /**
   * The observer for exporting the non-recoverable message to a file. This class handles the action
   * event triggered when the user wants to export the non-recoverable part of the message used in
   * the signature.
   */
  class ExportNonRecoverableMessageObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
      try {
        FileHandle.exportToFile("recoverableMessage.rsa",
            new String(signatureModel.getNonRecoverableM()));
        DisplayUtility.showInfoAlert("Export",
            "Non recoverable message was successfully exported!");
      } catch (Exception e) {
        e.printStackTrace();

      }
    }
  }

  /**
   * The observer for copying the non-recoverable message to the clipboard. This class handles the
   * action event triggered when the user wants to copy the non-recoverable part of the message to
   * the clipboard.
   */
  class CopyNonRecoverableMessageObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
      try {
        String nonRecoverableMessage = new String(signatureModel.getNonRecoverableM());
        DisplayUtility.copyToClipboard(nonRecoverableMessage, "Non-recoverable message");
      } catch (Exception e) {
        DisplayUtility.showErrorAlert("Failed to copy non-recoverable message to clipboard.");
      }
    }
  }

  /**
   * The observer for returning to the main menu. This class handles the action event triggered when
   * the user wishes to return to the main menu from the signature view.
   */
  class BackToMainMenuObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
      mainController.showMainMenuView();
      signView = null;
      verifyView = null;
      signatureModel = null;

    }
  }
}
