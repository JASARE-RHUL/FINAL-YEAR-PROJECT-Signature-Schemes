package uk.msci.project.rsa;

import java.io.IOException;
import java.math.BigInteger;

import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.stage.Stage;
import uk.msci.project.rsa.MainController;
import uk.msci.project.rsa.AbstractSignatureBaseController;
import uk.msci.project.rsa.SignView;
import uk.msci.project.rsa.SignatureModel;
import uk.msci.project.rsa.SignatureBaseView;

/**
 * This class is part of the controller component specific to digital
 * signature creations for non
 * batch operations. It is responsible for handling user interactions for the
 * signature creation
 * process. It also communicates with the Signature Model to perform the
 * actual signature creation
 * logic.
 */
public class SignatureCreationControllerStandard extends AbstractSignatureBaseController {

  /**
   * The view component of the MVC pattern for the signing functionality. It
   * handles the user
   * interface for the digital signature generation.
   */
  private SignView signView;

  /**
   * The message to be signed, stored as a byte array.
   */
  private byte[] message;


  /**
   * The digital signature generated after signing the message. It is stored
   * as a String for storage
   * purposes.
   */
  private String signature;


  /**
   * Constructs a SignatureCreationController with a reference to the
   * MainController to be used in
   * the event of the user initiating a switch back to main menu.
   *
   * @param mainController The main controller that this controller is part of.
   */
  public SignatureCreationControllerStandard(MainController mainController) {
    super(mainController);
  }

  /**
   * Loads the SignView FXML corresponding to a mode for the sign view (e.g.,
   * standard,
   * benchmarking, cross benchmarking) and initialises the view. This method
   * handles the setup for
   * different SignView modes based on the provided FXML path and runs the
   * observer setup and
   * additional setup based on mode.
   *
   * @param fxmlPath                   Path to the FXML file to load.
   * @param observerSetup              Runnable containing the observer setup
   *                                  logic.
   * @param additionalSetupBasedOnMode Runnable containing additional setup
   *                                   logic specific to the
   *                                   mode.
   */
  private void loadSignView(String fxmlPath, Runnable observerSetup,
                            Runnable additionalSetupBasedOnMode) {
    try {
      FXMLLoader loader = new FXMLLoader(getClass().getResource(fxmlPath));
      Parent root = loader.load();
      signView = loader.getController();

      observerSetup.run();
      additionalSetupBasedOnMode.run();

      mainController.setScene(root);
    } catch (IOException e) {
      e.printStackTrace();
    }
  }


  /**
   * Displays the SignView in standard mode. This method loads the SignView
   * for the standard
   * (non-benchmarking) mode. It initialises the view, sets up the required
   * observers for handling
   * events like text and key import, and displays the view on the provided
   * stage.
   *
   * @param primaryStage The primary stage of the application where the view
   *                     will be displayed.
   */
  public void showStandardView(Stage primaryStage) {
    isBenchmarkingMode = false;
    loadSignView("/SignViewStandardMode.fxml",
      () -> {
        this.signatureModel = new SignatureModel();
        setupObserversStandardMode(primaryStage, signView, signatureModel);
      },
      () -> preloadProvablySecureKey(signView));
  }

  /**
   * Displays the signature view in benchmarking mode. This method should
   * transition the user
   * interface to a state that supports benchmarking functionalities for
   * signature operations.
   *
   * @param primaryStage The primary stage of the application where the view
   *                     will be displayed.
   */
  @Override
  public void showBenchmarkingView(Stage primaryStage) {
    mainController.showSignatureCreationBenchmarking();
  }


  /**
   * Sets up observers for the SignView in the standard (non-benchmarking)
   * mode. This method
   * initialises observers for importing text, keys, canceling imports, and
   * creating signatures,
   * along with other functionalities specific to the standard signature
   * operation mode. It ensures
   * that all necessary UI elements respond correctly to user actions and
   * that the signature model
   * receives and processes user input as required for the standard digital
   * signature creation
   * process.
   *
   * @param primaryStage   The primary stage of the application where the
   *                       view will be displayed.
   * @param signatureView  The signature view for which observers are being
   *                       set up.
   * @param signatureModel The signature model associated with the signature
   *                       view, handling the data
   *                       and logic for signature creation.
   */
  @Override
  void setupObserversStandardMode(Stage primaryStage,
                                  SignatureBaseView signatureView,
                                  SignatureModel signatureModel) {
    super.setupObserversStandardMode(primaryStage, signView, signatureModel);
    signView.addCreateSignatureObserver(
      new CreateSignatureObserver());
  }

  /**
   * Initialises and sets up the post-generation observers for the SignView.
   * This includes observers
   * for copying the signature to the clipboard and exporting the signature.
   * This method is called
   * after a signature has been generated.
   */
  public void setupPostGenerationObservers() {
    signView.addCopySignatureObserver(new CopyToClipboardObserver("signature"
      , signature,
      "Failed to copy signature to clipboard."));
    signView.addExportSignatureObserver(
      new ExportObserver("signature.rsa", signature, "Signature was " +
        "successfully exported!"));

  }



  /**
   * The observer for creating signatures. This class handles the action
   * event triggered for the
   * signature generation process. It verifies necessary inputs, invokes the
   * signature generation
   * using the selected scheme, and updates the user interface with options
   * post-generation.
   */
  class CreateSignatureObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
      // Retrieve the hash output size set in the view
      hashOutputSize = signView.getHashOutputSizeArea();

      // Validate inputs: Ensure all necessary fields have been filled before
      // signature generation
      if ((signView.getTextInput().equals("") && message == null)
        || signatureModel.getKey() == null
        || signatureModel.getSignatureType() == null
        || signatureModel.getHashType() == null) {
        uk.msci.project.rsa.DisplayUtility.showErrorAlert(
          "You must provide an input for all fields. Please try again.");
        return; // Exit if validation fails
      }

      // Set the hash size in the model based on the view's configuration
      if (!setHashSizeInModel(signView)) {
        return; // Exit if hash size setup fails
      }

      try {
        // Retrieve the text to be signed from the view
        String textToSign = signView.getTextInput();

        // Convert the text to bytes if it is not empty
        if (!textToSign.equals("")) {
          message = textToSign.getBytes();
        }

        // Instantiate the signature scheme as per the selected configuration
        signatureModel.instantiateSignatureScheme();

        // Generate the signature and convert it to a string
        signature = new BigInteger(1, signatureModel.sign(message)).toString();

        // Setup observers for post-generation options
        setupPostGenerationObservers();

        // If there is a non-recoverable message part, set up options to
        // export or copy it
        if (signatureModel.getNonRecoverableM().length != 0) {
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

        // Reset any preloaded key parameters
        resetPreLoadedKeyParams();

        // Show a notification panel to inform the user of successful
        // signature generation
        signView.showNotificationPane();
      } catch (Exception e) {
        // Display an error alert if any issue occurs during the signature
        // generation
        uk.msci.project.rsa.DisplayUtility.showErrorAlert(
          "There was an error generating a signature. Please try again.");
        e.printStackTrace(); // Print stack trace for debugging
      }
    }
  }


  /**
   * Sets the message to be signed. This method is used to update the message
   * that will be signed by
   * the signature model.
   *
   * @param message The message to be signed, represented as a byte array.
   */
  @Override
  public void setMessage(byte[] message) {
    this.message = message;
  }

}
