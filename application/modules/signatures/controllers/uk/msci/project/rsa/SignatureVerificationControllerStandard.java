package uk.msci.project.rsa;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.stage.Stage;


/**
 * This class is part of the controller component specific to digital signature operations
 * responsible for handling user interactions for the signature verification process. It also
 * communicates with the Signature Model to perform the actual signature verification logic.
 */
public class SignatureVerificationControllerStandard extends AbstractSignatureBaseController {

  /**
   * The view component of the MVC pattern for the verification functionality. It handles the user
   * interface for the digital signature verification.
   */
  private VerifyView verifyView;


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
  public SignatureVerificationControllerStandard(MainController mainController) {
    super(mainController);
  }

  /**
   * Loads the VerifyView FXML corresponding to a mode for the verification view (e.g., standard,
   * benchmarking, cross benchmarking) and initialises the view. This method handles the setup for
   * different VerifyView modes based on the provided FXML path and runs the observer setup and
   * additional setup based on mode.
   *
   * @param fxmlPath                   Path to the FXML file to load.
   * @param observerSetup              Runnable containing the observer setup logic.
   * @param additionalSetupBasedOnMode Runnable containing additional setup logic specific to the
   *                                   mode.
   */
  private void loadVerifyView(String fxmlPath, Runnable observerSetup,
      Runnable additionalSetupBasedOnMode) {
    try {
      FXMLLoader loader = new FXMLLoader(getClass().getResource(fxmlPath));
      Parent root = loader.load();
      verifyView = loader.getController();

      observerSetup.run();
      additionalSetupBasedOnMode.run();

      mainController.setScene(root);
    } catch (IOException e) {
      e.printStackTrace();
    }
  }


  /**
   * Displays the VerifyView in standard mode. This method loads the VerifyView for the standard
   * (non-benchmarking) mode. It initialises the view, sets up the required observers for handling
   * events like text and key import, and displays the view on the provided stage.
   *
   * @param primaryStage The primary stage of the application where the view will be displayed.
   */
  public void showStandardMode(Stage primaryStage) {
    isBenchmarkingMode = false;
    loadVerifyView("/VerifyViewStandardMode.fxml",
        () -> {
          this.signatureModel = new SignatureModel();
          setupObserversStandardMode(primaryStage, verifyView, signatureModel);
        },
        () -> preloadProvablySecureKey(verifyView));
  }

  /**
   * Displays the signature view in benchmarking mode. This method should transition the user
   * interface to a state that supports benchmarking functionalities for signature operations.
   *
   * @param primaryStage The primary stage of the application where the view will be displayed.
   */
  @Override
  public void showBenchmarkingView(Stage primaryStage) {
    mainController.showSignatureVerificationBenchmarking();
  }

  /**
   * Sets up observers for the VerifyView in the standard (non-benchmarking) mode for signature
   * verification. This method initialises observers for importing signatures, keys, handling
   * signature verification, and other standard mode functionalities. It is essential for managing
   * user interactions and facilitating the verification process.
   *
   * @param primaryStage   The primary stage of the application where the view will be displayed.
   * @param signatureView  The signature view associated with this controller.
   * @param signatureModel The signature model used for verification processes.
   */
  @Override
  public void setupObserversStandardMode(Stage primaryStage, SignatureBaseView signatureView,
      SignatureModel signatureModel) {
    super.setupObserversStandardMode(primaryStage, verifyView, signatureModel);
    verifyView.addImportSigButtonObserver(
        new ImportObserver(primaryStage, verifyView, null, this::handleSig, "*.rsa"));
    verifyView.addCancelImportSignatureButtonObserver(
        new CancelImportSignatureButtonObserver());
    verifyView.addVerifyBtnObserver(
        new VerifyBtnObserver());
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
   * Handles the importing of a signature file. The method reads the signature data from the file,
   * updates the signature model with the content, and reflects the changes on the view to indicate
   * that the signature has been successfully imported. This is crucial in the signature
   * verification process where the imported signature is used for verification against a message.
   *
   * @param file           The signature file selected by the user for verification.
   * @param signatureView  The signature view to be updated with the imported signature.
   * @param signatureModel The signature model used in the verification process.
   */
  public void handleSig(File file, SignatureBaseView signatureView,
      SignatureModel signatureModel) {
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
    verifyView.setImportSigButtonVisibility(false);
    verifyView.setCancelImportSignatureButtonVisibility(true);
  }


  /**
   * The observer for verifying signatures. This class handles the action event triggered for the
   * signature verification process. It checks for necessary inputs, verifies the signature using
   * the selected scheme, and updates the view with the verification result.
   */
  class VerifyBtnObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
      hashOutputSize = verifyView.getHashOutputSizeArea();
      if ((verifyView.getTextInput().equals("") && message == null)) {
        if ((signatureModel.getSignatureType() != SignatureType.ISO_IEC_9796_2_SCHEME_1)) {
          uk.msci.project.rsa.DisplayUtility.showErrorAlert(
              "You must provide an input for all required fields. Please try again.");
          return;
        }
      }
      if (!setHashSizeInModel(verifyView)) {
        return;
      }
      if (signatureModel.getKey() == null
          || signatureModel.getSignatureType() == null
          || (verifyView.getSigText().equals("") && signature == null)
          || signatureModel.getHashType() == null) {
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

        byte[] signatureBytes = new byte[0];
        try {
          signatureBytes = new BigInteger(signature).toByteArray();
        } catch (Exception ignored) {
        }

        signatureModel.instantiateSignatureScheme();
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
        resetPreLoadedKeyParams();
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

  /**
   * Observer for canceling the import of a signature in non benchmarking mode. Handles the event
   * when the user decides to cancel the import of the signature by replacing the cancel button with
   * the original import button and resetting corresponding text field that display the name of the
   * file.
   */
  class CancelImportSignatureButtonObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
      verifyView.setSigFileCheckmarkImageVisibility(false);
      verifyView.setSigFileNameLabel("");
      verifyView.setSigFileHBoxVisibility(false);
      verifyView.setSignatureTextVisibility(true);
      verifyView.setCancelImportSignatureButtonVisibility(false);
      verifyView.setImportSigButtonVisibility(true);

    }
  }

}
