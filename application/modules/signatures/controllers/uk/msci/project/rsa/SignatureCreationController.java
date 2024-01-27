package uk.msci.project.rsa;

import java.io.IOException;
import java.math.BigInteger;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;


/**
 * This class is part of the controller component specific to digital signature operations
 * responsible for handling user interactions for the signature creation process. It also
 * communicates with the Signature Model to perform the actual signature creation logic.
 */
public class SignatureCreationController extends SignatureBaseController {

  /**
   * The view component of the MVC pattern for the signing functionality. It handles the user
   * interface for the digital signature generation.
   */
  private SignView signView;

  /**
   * The message to be signed, stored as a byte array.
   */
  private byte[] message;


  /**
   * The digital signature generated after signing the message. It is stored as a String for storage
   * purposes.
   */
  private String signature;

  /**
   * Constructs a SignatureCreationController with a reference to the MainController to be used in
   * the event of the user initiating a switch back to main menu.
   *
   * @param mainController The main controller that this controller is part of.
   */
  public SignatureCreationController(MainController mainController) {
    super(mainController);
  }

  /**
   * Initialises and displays the SignView stage. It loads the FXML for the SignView and sets up the
   * scene and the stage.
   *
   * @param primaryStage The primary stage for this application.
   */
  public void showSignView(Stage primaryStage) {
    try {
      FXMLLoader loader = new FXMLLoader(getClass().getResource("/SignView.fxml"));
      Parent root = loader.load();
      signView = loader.getController();
      this.signatureModel = new SignatureModel();

      // Set up observers for SignView
      setupSignObservers(primaryStage);

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
  private void setupSignObservers(Stage primaryStage) {
    signView.addImportTextObserver(
        new ImportObserver(primaryStage, new SignViewUpdateOperations(signView),
            this::handleMessageFile, "*.txt"));
    signView.addImportKeyObserver(
        new ImportObserver(primaryStage, new SignViewUpdateOperations(signView),
            this::handleKey, "*.rsa"));
    signView.addSignatureSchemeChangeObserver(new SignatureSchemeChangeObserver());
    signView.addCreateSignatureObserver(new CreateSignatureObserver());
    signView.addBackToMainMenuObserver(new BackToMainMenuObserver(signView));
    signView.addCloseNotificationObserver(new BackToMainMenuObserver(signView));
  }

  /**
   * Initialises and sets up the post-generation observers for the SignView. This includes observers
   * for copying the signature to the clipboard and exporting the signature. This method is called
   * after a signature has been generated.
   */
  public void setupPostGenerationObservers() {
    signView.addCopySignatureObserver(new CopyToClipboardObserver("signature", signature,
        "Failed to copy signature to clipboard."));
    signView.addExportSignatureObserver(
        new ExportObserver("signature.rsa", signature, "Signature was successfully exported!"));

  }


  /**
   * The observer for creating signatures. This class handles the action event triggered for the
   * signature generation process. It checks for necessary inputs, generates the signature using the
   * selected scheme, and updates the view with post-generation options.
   */
  class CreateSignatureObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
      if ((signView.getTextInput().equals("") && message == null)
          || signatureModel.getKey() == null
          || signView.getSelectedSignatureScheme() == null) {
        uk.msci.project.rsa.DisplayUtility.showErrorAlert(
            "You must provide an input for all fields. Please try again.");
        return;
      }
      try {
        String textToSign = signView.getTextInput();
        if (!textToSign.equals("")) {
          message = textToSign.getBytes();
        }
        signatureModel.instantiateSignatureScheme();

        signature = new BigInteger(1, signatureModel.sign(message)).toString();
        setupPostGenerationObservers();
        if (signatureModel.getNonRecoverableM() != null) {
          signView.addExportNonRecoverableMessageObserver(
              new ExportObserver("nonRecoverableMessage.txt",
                  new String(signatureModel.getNonRecoverableM()),
                  "Non recoverable message was successfully exported!"));
          signView.addCopyNonRecoverableMessageObserver(
              new CopyToClipboardObserver("Non-recoverable message",
                  new String(signatureModel.getNonRecoverableM()),
                  "Failed to copy non-recoverable message to clipboard."));
          signView.setRecoveryOptionsVisibility(true);
        }
        signView.showNotificationPane();
      } catch (Exception e) {
        uk.msci.project.rsa.DisplayUtility.showErrorAlert(
            "There was an error generating a signature. Please try again.");
        e.printStackTrace();

      }
    }
  }


  /**
   * Sets the message to be signed. This method is used to update the message that will be signed by
   * the signature model.
   *
   * @param message The message to be signed, represented as a byte array.
   */
  @Override
  public void setMessage(byte[] message) {
    this.message = message;
  }

}
