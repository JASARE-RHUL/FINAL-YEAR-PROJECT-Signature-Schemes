package uk.msci.project.rsa;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import javafx.application.Platform;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.concurrent.Task;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.control.ButtonType;
import javafx.scene.control.Dialog;
import javafx.scene.control.Label;
import javafx.scene.control.ProgressBar;
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

  private int numSignatures;


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
   * Initialises and displays the VerifyView in benchmarking mode. This method loads the FXML for
   * the VerifyView, sets up the user interface scene, and configures the stage for the
   * application.
   *
   * @param primaryStage The primary stage for this application upon which the standard mode
   *                     verification view will be set. This stage is used as the main window for
   *                     the application.
   */
  public void showVerifyView(Stage primaryStage) {
    if (isKeyForComparisonMode && isCrossParameterBenchmarkingEnabled) {
      showVerifyViewCrossBenchmarkingMode(primaryStage);
      return;
    }
    try {
      FXMLLoader loader = new FXMLLoader(getClass().getResource("/VerifyView.fxml"));
      Parent root = loader.load();
      verifyView = loader.getController();
      signatureModel = new SignatureModel();

      // Set up observers for benchmarking mode VerifyView
      verifyView.addBenchmarkingModeToggleObserver(
          new SignatureBaseController.ApplicationModeChangeObserver(
              () -> showVerifyViewStandardMode(primaryStage),
              () -> showVerifyView(primaryStage)
          ));
      verifyView.addCrossParameterToggleObserver(new CrossBenchmarkingModeChangeObserver(
          () -> showVerifyViewCrossBenchmarkingMode(primaryStage),
          () -> showVerifyView(primaryStage), new VerifyViewUpdateOperations(verifyView)));
      setupVerificationObserversBenchmarking(primaryStage);
      if (isKeyProvablySecure && this.importedKeyBatch != null
          && !isCrossParameterBenchmarkingEnabled) {
        updateWithImportedKey(new VerifyViewUpdateOperations(verifyView));
        verifyView.setImportKeyBatchButtonVisibility(false);
        verifyView.setCancelImportKeyButtonVisibility(true);
        verifyView.setProvableParamsHboxVisibility(true);
        verifyView.setProvablySecureParametersRadioSelected(true);
        verifyView.setCustomParametersRadioVisibility(false);
        verifyView.setStandardParametersRadioVisibility(false);
      }

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
  public void showVerifyViewStandardMode(Stage primaryStage) {
    try {
      FXMLLoader loader = new FXMLLoader(getClass().getResource("/VerifyViewStandardMode.fxml"));
      Parent root = loader.load();
      verifyView = loader.getController();
      signatureModel = new SignatureModel();
      verifyView.addBenchmarkingModeToggleObserver(
          new SignatureBaseController.ApplicationModeChangeObserver(
              () -> showVerifyViewStandardMode(primaryStage),
              () -> showVerifyView(primaryStage)
          ));
      setupVerifyObservers(primaryStage);
      mainController.setScene(root);

    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  /**
   * Displays the VerifyView in cross-parameter benchmarking mode. This method loads the VerifyView
   * specifically configured for cross-parameter benchmarking. It initialises the view, sets up the
   * necessary observers for handling key and message batch imports, and displays the view on the
   * provided stage.
   *
   * @param primaryStage The primary stage of the application where the view will be displayed.
   */
  public void showVerifyViewCrossBenchmarkingMode(Stage primaryStage) {
    try {
      FXMLLoader loader = new FXMLLoader(
          getClass().getResource("/VerifyViewCrossBenchmarkingMode.fxml"));
      Parent root = loader.load();
      verifyView = loader.getController();
      this.signatureModel = new SignatureModel();
      updateWithImportedKey(new VerifyViewUpdateOperations(verifyView));
      if (isCrossParameterBenchmarkingEnabled && this.importedKeyBatch != null) {
        verifyView.setImportKeyBatchButtonVisibility(false);
        verifyView.setCancelImportKeyButtonVisibility(true);
      }
      verifyView.addBenchmarkingModeToggleObserver(
          new SignatureBaseController.ApplicationModeChangeObserver(
              () -> showVerifyViewStandardMode(primaryStage),
              () -> showVerifyView(primaryStage)
          ));
      verifyView.addCrossParameterToggleObserver(new CrossBenchmarkingModeChangeObserver(
          () -> showVerifyViewCrossBenchmarkingMode(primaryStage),
          () -> showVerifyView(primaryStage), new VerifyViewUpdateOperations(verifyView)));
      setupVerificationObserversCrossBenchmarking(primaryStage);

      mainController.setScene(root);

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
    verifyView.addCancelImportSingleKeyButtonObserver(
        new CancelImportKeyButtonObserver(new VerifyViewUpdateOperations(verifyView)));
    verifyView.addSignatureSchemeChangeObserver(new SignatureSchemeChangeObserver());
    verifyView.addBackToMainMenuObserver(new BackToMainMenuObserver(verifyView));
    verifyView.addImportSigButtonObserver(
        new ImportObserver(primaryStage, null, this::handleSig, "*.rsa"));
    verifyView.addParameterChoiceChangeObserver(
        new ParameterChoiceChangeObserver(new VerifyViewUpdateOperations(verifyView)));
    verifyView.addHashFunctionChangeObserver(
        new HashFunctionChangeObserver(new VerifyViewUpdateOperations(verifyView)));
    verifyView.addVerifyBtnObserver(
        new VerifyBtnObserver(new VerifyViewUpdateOperations(verifyView)));
    verifyView.addCloseNotificationObserver(new BackToMainMenuObserver(verifyView));
    verifyView.addCancelImportTextButtonObserver(
        new CancelImportTextButtonObserver(new VerifyViewUpdateOperations(verifyView)));
    verifyView.addCancelImportSignatureButtonObserver(
        new CancelImportSignatureButtonObserver());
  }

  /**
   * Sets up benchmarking mode specific observers for the verification view controls.
   *
   * @param primaryStage The stage that observers will use for file dialogs.
   */
  private void setupVerificationObserversBenchmarking(Stage primaryStage) {
    verifyView.addImportTextBatchBtnObserver(
        new ImportObserver(primaryStage, new VerifyViewUpdateOperations(verifyView),
            this::handleMessageBatch, "*.txt"));
    verifyView.addImportKeyBatchButtonObserver(
        new ImportObserver(primaryStage, new VerifyViewUpdateOperations(verifyView),
            this::handleKeyBatch, "*.rsa"));
    verifyView.addCancelImportKeyButtonObserver(
        new CancelImportKeyBatchButtonObserver(new VerifyViewUpdateOperations(verifyView)));
    verifyView.addImportSigBatchButtonObserver(
        new ImportObserver(primaryStage, new VerifyViewUpdateOperations(verifyView),
            this::handleSignatureBatch, "*.rsa"));
    verifyView.addSignatureSchemeChangeObserver(new SignatureSchemeChangeObserver());
    verifyView.addParameterChoiceChangeObserver(
        new ParameterChoiceChangeObserver(new VerifyViewUpdateOperations(verifyView)));
    verifyView.addHashFunctionChangeObserver(
        new HashFunctionChangeObserver(new VerifyViewUpdateOperations(verifyView)));
    verifyView.addVerificationBenchmarkButtonObserver(
        new VerificationBenchmarkButtonObserver(new VerifyViewUpdateOperations(verifyView)));
    verifyView.addBackToMainMenuObserver(new BackToMainMenuObserver(verifyView));
    verifyView.addProvableSchemeChangeObserver(
        new ProvableParamsChangeObserver(new VerifyViewUpdateOperations(verifyView)));
  }

  /**
   * Displays the VerifyView in cross-parameter benchmarking mode. This method loads the VerifyView
   * specifically configured for cross-parameter benchmarking. It initialises the view, sets up the
   * necessary observers for handling key and message batch imports, and displays the view on the
   * provided stage.
   *
   * @param primaryStage The primary stage of the application where the view will be displayed.
   */
  private void setupVerificationObserversCrossBenchmarking(Stage primaryStage) {
    verifyView.addImportTextBatchBtnObserver(
        new ImportObserver(primaryStage, new VerifyViewUpdateOperations(verifyView),
            this::handleMessageBatch, "*.txt"));
    verifyView.addImportKeyBatchButtonObserver(
        new ImportObserver(primaryStage, new VerifyViewUpdateOperations(verifyView),
            this::handleKeyBatch, "*.rsa"));
    verifyView.addImportSigBatchButtonObserver(
        new ImportObserver(primaryStage, new VerifyViewUpdateOperations(verifyView),
            this::handleSignatureBatch, "*.rsa"));
    verifyView.addCancelImportKeyButtonObserver(
        new CancelImportKeyBatchButtonObserver(new VerifyViewUpdateOperations(verifyView)));
    verifyView.addSignatureSchemeChangeObserver(new SignatureSchemeChangeObserver());
    verifyView.addVerificationBenchmarkButtonObserver(
        new VerificationBenchmarkButtonObserver(new VerifyViewUpdateOperations(verifyView)));
    verifyView.addBackToMainMenuObserver(new BackToMainMenuObserver(verifyView));
    verifyView.addStandardHashFunctionChangeObserver(new StandardHashFunctionChangeObserver());
    verifyView.addProvableHashFunctionChangeObserver(new ProvableHashFunctionChangeObserver());

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
    verifyView.setImportSigButtonVisibility(false);
    verifyView.setCancelImportSignatureButtonVisibility(true);
  }

  /**
   * The observer for verifying signatures. This class handles the action event triggered for the
   * signature verification process. It checks for necessary inputs, verifies the signature using
   * the selected scheme, and updates the view with the verification result.
   */
  class VerifyBtnObserver implements EventHandler<ActionEvent> {

    private ViewUpdate viewOps;

    public VerifyBtnObserver(ViewUpdate viewOps) {
      this.viewOps = viewOps;
    }

    @Override
    public void handle(ActionEvent event) {
      hashOutputSize = verifyView.getHashOutputSize();
      if ((verifyView.getTextInput().equals("") && message == null)) {
        if ((signatureModel.getSignatureType() != SignatureType.ISO_IEC_9796_2_SCHEME_1)) {
          uk.msci.project.rsa.DisplayUtility.showErrorAlert(
              "You must provide an input for all required fields. Please try again.");
          return;
        }
      }
      if (!handleHashOutputSize(viewOps) && verifyView.getHashOutputSizeFieldVisibility()) {
        return;
      } else if (verifyView.getHashOutputSizeFieldVisibility()) {
        signatureModel.setHashSize((Integer.parseInt(hashOutputSize) + 7) / 8);
      }
      if (signatureModel.getKey() == null
          || signatureModel.getSignatureType() == null
          || (verifyView.getSigText().equals("") && signature == null)
          || verifyView.getSelectedHashFunction() == null) {
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
   * Observer for initiating the signature verification benchmark. Handles the event triggered for
   * starting the benchmarking process, sets up the task, and shows the progress on the UI.
   */
  class VerificationBenchmarkButtonObserver implements EventHandler<ActionEvent> {

    private ViewUpdate viewOps;

    public VerificationBenchmarkButtonObserver(ViewUpdate viewOps) {
      this.viewOps = viewOps;
    }

    @Override
    public void handle(ActionEvent event) {
      hashOutputSize = verifyView.getHashOutputSize();
      if (signatureModel.getNumTrials() * signatureModel.getPublicKeyBatchLength()
          != numSignatures) {
        uk.msci.project.rsa.DisplayUtility.showErrorAlert(
            "The numbers of messages and signatures do not match. Please ensure they match for a valid set of verification pairings.");
        return;
      }
      if ((signatureModel.getNumTrials() == 0)
          || signatureModel.getPublicKeyBatchLength() == 0
          || verifyView.getSelectedSignatureScheme() == null || numSignatures == 0
          || verifyView.getSelectedHashFunction() == null || (isCrossParameterBenchmarkingEnabled
          && (verifyView.getCurrentStandardHashFunction()
          .equals("") || verifyView.getCurrentProvableHashFunction().equals("")))) {
        uk.msci.project.rsa.DisplayUtility.showErrorAlert(
            "You must provide an input for all fields. Please try again.");
        return;
      }
      if (!handleHashOutputSize(viewOps) && verifyView.getHashOutputSizeFieldVisibility()) {
        return;
      } else if (verifyView.getHashOutputSizeFieldVisibility()) {
        signatureModel.setHashSize((Integer.parseInt(hashOutputSize) + 7) / 8);
      }

      // Show the progress dialog
      Dialog<Void> progressDialog = uk.msci.project.rsa.DisplayUtility.showProgressDialog(
          mainController.getPrimaryStage(), "Signature Generation");
      ProgressBar progressBar = (ProgressBar) progressDialog.getDialogPane()
          .lookup("#progressBar");
      Label progressLabel = (Label) progressDialog.getDialogPane().lookup("#progressLabel");

      Task<Void> benchmarkingTask = createBenchmarkingTask(messageBatchFile, signatureBatchFile,
          progressBar, progressLabel);
      new Thread(benchmarkingTask).start();

      progressDialog.getDialogPane().lookupButton(ButtonType.CANCEL)
          .addEventFilter(ActionEvent.ACTION, e -> {
            if (benchmarkingTask.isRunning()) {
              benchmarkingTask.cancel();
            }
          });

      benchmarkingTask.setOnSucceeded(e -> {
        progressDialog.close();
        handleBenchmarkingCompletion(); // Handle completion

      });

      benchmarkingTask.setOnFailed(e -> {
        progressDialog.close();
        uk.msci.project.rsa.DisplayUtility.showErrorAlert(
            "Error: Benchmarking failed. Please try again.");

      });

    }
  }


  /**
   * Creates a benchmarking task for signature generation. This task is responsible for processing a
   * batch of messages, generating signatures, and updating the UI with progress.
   *
   * @param messageFile   The file containing the messages to be signed.
   * @param progressBar   UI component to display progress.
   * @param progressLabel UI component to display progress text.
   * @return The task to be executed for benchmarking.
   */

  private Task<Void> createBenchmarkingTask(File messageFile, File batchSignatureFile,
      ProgressBar progressBar,
      Label progressLabel) {
    return new Task<>() {
      @Override
      protected Void call() throws Exception {
        signatureModel.batchVerifySignatures(messageFile, batchSignatureFile,
            progress -> Platform.runLater(() -> {
              progressBar.setProgress(progress);
              progressLabel.setText(String.format("%.0f%%", progress * 100));
            }));
        return null;
      }
    };

  }

  /**
   * Handles the completion of the benchmarking task for signature verification. This method is
   * called when the benchmarking task successfully completes. It initialises and sets up the
   * ResultsController with the appropriate context (SignatureVerificationContext) and displays the
   * results view with the gathered benchmarking data.
   */
  private void handleBenchmarkingCompletion() {
    ResultsController resultsController = new ResultsController(mainController);
    BenchmarkingContext context = new SignatureVerificationContext(signatureModel);
    resultsController.setContext(context);
    resultsController.showResultsView(mainController.getPrimaryStage(),
        signatureModel.getClockTimesPerTrial(), signatureModel.getPublicKeyLengths());
  }

  /**
   * Observer for canceling the import of a text batch. Handles the event when the user decides to
   * cancel the import of a batch of messages by replacing the cancel button with the original
   * import button and resetting corresponding text field that display the name of the file.
   */
  class CancelImportTextBatchButtonObserver implements EventHandler<ActionEvent> {

    private ViewUpdate viewOps;

    public CancelImportTextBatchButtonObserver(ViewUpdate viewOps) {
      this.viewOps = viewOps;
    }

    @Override
    public void handle(ActionEvent event) {
      viewOps.setTextFileCheckmarkVisibility(false);
      viewOps.setMessageBatchName("Please Import a message batch");
      messageBatchFile = null;
      verifyView.setImportTextBatchBtnVisibility(true);
      verifyView.setCancelImportTextButtonVisibility(false);
    }
  }


  /**
   * Observer for canceling the import of a signature batch. Handles the event when the user decides
   * to cancel the import of a batch of signatures.
   */
  class CancelImportSigButtonObserver implements EventHandler<ActionEvent> {


    @Override
    public void handle(ActionEvent event) {
      verifyView.setSigFileCheckmarkImageVisibility(false);
      verifyView.setSignatureBatch("Please Import a signature batch");
      messageBatchFile = null;
      verifyView.setImportSigBatchBtnVisibility(true);
      verifyView.setCancelImportSigBatchButtonVisibility(false);
    }
  }

  /**
   * Processes a file containing a batch of messages for signature verification. Validates the
   * file's content and updates the model and UI accordingly. Ensures the file format is correct
   * (Ensures the file format is correct i.e., no empty lines apart from the end of the file).
   *
   * @param file    The file containing messages to be signed.
   * @param viewOps Operations to update the view based on file processing.
   */
  public void handleMessageBatch(File file, ViewUpdate viewOps) {
    int numTrials = checkFileForNonEmptyLines(file, "message");
    if (numTrials > 0) {
      messageBatchFile = file;
      signatureModel.setNumTrials(numTrials);
      viewOps.setMessageBatchName(file.getName());
      viewOps.setTextFileCheckmarkImage();
      viewOps.setTextFileCheckmarkVisibility(true);
      viewOps.setBatchMessageVisibility(true);
      viewOps.setImportTextBatchBtnVisibility(false);
      viewOps.setCancelImportTextButtonVisibility(true);
      verifyView.addCancelImportTextButtonObserver(
          new CancelImportTextBatchButtonObserver(new VerifyViewUpdateOperations(verifyView)));
    }
  }

  /**
   * Handles the file selected by the user for a batch of keys. It validates the keys and updates
   * the model and view accordingly. It expects the key file to contain a line separated text of
   * comma delimited positive integers and updates the view based on the result of the key
   * validation.
   *
   * @param file    The file selected by the user containing a batch of keys.
   * @param viewOps The {@code ViewUpdate} operations that will update the view.
   */
  public boolean handleKeyBatch(File file, ViewUpdate viewOps) {
    if (super.handleKeyBatch(file, viewOps)) {
      verifyView.setImportKeyBatchButtonVisibility(false);
      verifyView.setCancelImportKeyButtonVisibility(true);
    }
    return true;
  }


  /**
   * Processes a file containing a batch of signatures for signature verification. Validates the
   * file's content and updates the model and UI accordingly. Ensures the file format is correct
   * (Ensures the file format is correct i.e., no empty lines apart from the end of the file).
   *
   * @param file    The file containing messages to be signed.
   * @param viewOps Operations to update the view based on file processing.
   */
  public void handleSignatureBatch(File file, ViewUpdate viewOps) {
    numSignatures = checkFileForNonEmptyLines(file, "signature");
    if (numSignatures > 0) {
      signatureBatchFile = file;
      verifyView.setSignatureBatch(file.getName());
      verifyView.setSigFileCheckmarkImage();
      verifyView.setSigFileCheckmarkImageVisibility(true);
      verifyView.setSignatureBatchFieldVisibility(true);
      verifyView.setImportSigBatchBtnVisibility(false);
      verifyView.setCancelImportSigBatchButtonVisibility(true);
      verifyView.addCancelImportSigBatchButtonObserver(
          new CancelImportSigButtonObserver());
    } else {
      uk.msci.project.rsa.DisplayUtility.showErrorAlert(
          "Invalid signature batch. Please make sure the file is not empty.");
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
   * Observer for application mode changes in the Signing view. This observer observes for changes
   * in the toggle switch that switches between standard and benchmarking modes in the signature
   * creation view. When the mode changes, it sets up the corresponding view and clears any previous
   * state such as selected messages or keys.
   */
  class ApplicationModeChangeObserver implements ChangeListener<Boolean> {

    @Override
    public void changed(ObservableValue<? extends Boolean> observableValue, Boolean oldValue,
        Boolean newValue) {
      // Checks if the new value of the toggle is TRUE (e.g., switched on)
      if (Boolean.TRUE.equals(newValue)) {
        // Further checks if the old value was FALSE, indicating a change from off to on
        if (Boolean.FALSE.equals(oldValue)) {
          // If the toggle is switched on, the application initializes the sign view for benchmarking mode
          showVerifyView(mainController.getPrimaryStage());
          // Clears any existing message data, as the mode change might require different data handling
          message = null;
        }
      } else {
        // If the new value is not TRUE (i.e., the toggle is switched off), checks if it was previously on
        if (Boolean.TRUE.equals(oldValue)) {
          // Initializes the sign view for the standard mode, as the toggle is switched off
          showVerifyViewStandardMode(mainController.getPrimaryStage());
          // Clears any existing batch file data, as it's not needed in standard mode
          messageBatchFile = null;
        }
      }
    }

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
