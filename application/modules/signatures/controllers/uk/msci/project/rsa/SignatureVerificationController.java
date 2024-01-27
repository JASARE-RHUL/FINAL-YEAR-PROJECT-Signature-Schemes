package uk.msci.project.rsa;

import java.io.File;
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
 * responsible for handling user interactions for the signature verification process. It also
 * communicates with the Signature Model to perform the actual signature verification logic.
 */
public class SignatureVerificationController extends SignatureBaseController {

  /**
   * The view component of the MVC pattern for the verification functionality. It handles the user
   * interface for the digital signature verification.
   */
  private VerifyView verifyView;

  /**
   * The message to be verified, stored as a byte array.
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
  public SignatureVerificationController(MainController mainController) {
    super(mainController);
  }

  /**
   * Initialises and displays the verifyView stage. It loads the FXML for the verifyView and sets up
   * the scene and the stage.
   *
   * @param primaryStage The primary stage for this application.
   */
  public void showVerifyView(Stage primaryStage) {
    try {
      FXMLLoader loader = new FXMLLoader(getClass().getResource("/VerifyView.fxml"));
      Parent root = loader.load();
      verifyView = loader.getController();
      signatureModel = new SignatureModel();

      // Set up observers for SignView
      setupVerifyObservers(primaryStage);

      primaryStage.setScene(new Scene(root));
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  /**
   * Sets up observers for the VerifyView controls. Observers are added to handle events like text
   * import, key import, and signature scheme changes.
   *
   * @param primaryStage The stage that observers will use for file dialogs.
   */
  public void setupVerifyObservers(Stage primaryStage) {
    verifyView.addImportTextObserver(
        new ImportObserver(primaryStage, new VerifyViewUpdateOperations(verifyView),
            this::handleMessageFile, "*.txt"));
    verifyView.addImportKeyObserver(
        new ImportObserver(primaryStage, new VerifyViewUpdateOperations(verifyView),
            this::handleKey, "*.rsa"));
    verifyView.addSignatureSchemeChangeObserver(new SignatureSchemeChangeObserver());
    verifyView.addBackToMainMenuObserver(new BackToMainMenuObserver(verifyView));
    verifyView.addImportSigButtonObserver(
        new ImportObserver(primaryStage, null, this::handleSig, "*.rsa"));
    verifyView.addVerifyBtnObserver(new VerifyBtnObserver());
    verifyView.addCloseNotificationObserver(new BackToMainMenuObserver(verifyView));
  }

  /**
   * Initialises and sets up the post-verification observers for the VerifyView. This includes
   * observers for exporting and copying the recoverable message (if applicable). This method is
   * called after a signature has been successfully verified.
   */
  public void setupPostVerificationObservers() {
    verifyView.addExportRecoverableMessageObserver(new ExportObserver("recoverableMessage.txt",
        new String(signatureModel.getRecoverableM()),
        "Recoverable message was successfully exported!"));
    verifyView.addCopyRecoverableMessageObserver(
        new CopyToClipboardObserver("Recoverable message",
            new String(signatureModel.getRecoverableM()),
            "Failed to copy recoverable message to clipboard."));
  }


  /**
   * Handles the importing of a signature file. It updates the signature model with the content of
   * the file and updates the view to reflect the signature has been loaded.
   *
   * @param file    The signature file selected by the user.
   * @param viewOps Not applicable for importing of a signature.
   */
  public void handleSig(File file, ViewUpdate viewOps) {
    String content = "";
    try {
      content = FileHandle.importFromFile(file);
    } catch (Exception e) {
      uk.msci.project.rsa.DisplayUtility.showErrorAlert("Error importing file, please try again.");
    }
    signature = content;
    verifyView.setSignatureText("");
    verifyView.setSigFileCheckmarkImage();
    verifyView.setSigFileCheckmarkImageVisibility(true);
    verifyView.setSigFileNameLabel("Signature imported");
    verifyView.setSignatureTextVisibility(false);
    verifyView.setSigFileHBoxVisibility(true);
  }

  /**
   * The observer for verifying signatures. This class handles the action event triggered for the
   * signature verification process. It checks for necessary inputs, verifies the signature using
   * the selected scheme, and updates the view with the verification result.
   */
  class VerifyBtnObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
      if ((verifyView.getTextInput().equals("") && message == null)) {
        if ((signatureModel.getSigType() != SignatureType.ISO_IEC_9796_2_SCHEME_1)) {
          uk.msci.project.rsa.DisplayUtility.showErrorAlert(
              "You must provide an input for all required fields. Please try again.");
          return;
        }
      }
      if (signatureModel.getKey() == null
          || signatureModel.getSigType() == null
          || (verifyView.getSigText().equals("") && signature == null)) {
        uk.msci.project.rsa.DisplayUtility.showErrorAlert(
            "You must provide an input for all required fields. Please try again.");
        return;
      }
      try {
        String textToVerify = verifyView.getTextInput();
        if (!textToVerify.equals("")) {
          message = textToVerify.getBytes();
        }
        String signatureInput = verifyView.getSigText();
        if (!signatureInput.equals("")) {
          signature = signatureInput;
        }

        signatureModel.instantiateSignatureScheme();

        byte[] signatureBytes = new byte[0];
        try {
          signatureBytes = new BigInteger(signature).toByteArray();
        } catch (Exception e) {

        }

        boolean verificationResult = signatureModel.verify(message, signatureBytes);
        if (verificationResult) {
          verifyView.setTrueLabelVisibility(true);
          if (signatureModel.getRecoverableM() != null) {
            setupPostVerificationObservers();
            verifyView.setRecoveryOptionsVisibility(true);
          }
        } else {
          verifyView.setFalseLabelVisibility(true);
        }
        verifyView.showNotificationPane();

      } catch (Exception e) {
        uk.msci.project.rsa.DisplayUtility.showErrorAlert(
            "There was an error in the verification process. Please try again.");
        e.printStackTrace();

      }
    }
  }

  /**
   * Sets the message to be verified. This method is used to update the message that will be
   * verified by the signature model.
   *
   * @param message The message to be verified, represented as a byte array.
   */
  @Override
  public void setMessage(byte[] message) {
    this.message = message;
  }

}
