package uk.msci.project.rsa;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import javafx.application.Platform;
import javafx.concurrent.Task;
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
   * The number of signatures involved in the batch verification process. This field holds the total
   * count of signatures that will be verified during the benchmarking task.
   */
  private int numSignatures;

  /**
   * An instance of the BenchmarkingUtility class used to manage benchmarking tasks. This utility
   * facilitates the execution and monitoring of tasks related to the benchmarking of signature
   * verification processes. It provides methods to initiate benchmarking tasks, update progress,
   * and handle task completion.
   */
  private BenchmarkingUtility benchmarkingUtility;


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
      this.signatureModel = new SignatureModel();

      observerSetup.run();
      additionalSetupBasedOnMode.run();

      mainController.setScene(root);
    } catch (IOException e) {
      e.printStackTrace();
    }
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
    loadVerifyView("/VerifyView.fxml", () -> setupVerificationObserversBenchmarking(primaryStage),
        () -> {
          if (isSingleKeyProvablySecure && this.importedKeyBatch != null
              && !isCrossParameterBenchmarkingEnabled) {
            updateWithImportedKeyBatch(new VerifyViewUpdateOperations(verifyView));
            verifyView.setImportKeyBatchButtonVisibility(false);
            verifyView.setCancelImportKeyButtonVisibility(true);
            verifyView.setProvableParamsHboxVisibility(true);
            verifyView.setProvablySecureParametersRadioSelected(true);
            verifyView.setCustomParametersRadioVisibility(false);
            verifyView.setStandardParametersRadioVisibility(false);
          }
        });
  }

  /**
   * Displays the VerifyView in standard mode. This method loads the VerifyView for the standard
   * (non-benchmarking) mode. It initialises the view, sets up the required observers for handling
   * events like text and key import, and displays the view on the provided stage.
   *
   * @param primaryStage The primary stage of the application where the view will be displayed.
   */
  public void showVerifyViewStandardMode(Stage primaryStage) {
    loadVerifyView("/VerifyViewStandardMode.fxml",
        () -> setupVerificationObserversStandard(primaryStage),
        () -> {
          if (isSingleKeyProvablySecure && this.importedKeyBatch != null) {
            updateWithImportedKey(new VerifyViewUpdateOperations(verifyView));
            verifyView.setImportKeyButtonVisibility(false);
            verifyView.setCancelImportSingleKeyButtonVisibility(true);
            verifyView.setProvableParamsHboxVisibility(true);
            verifyView.setProvablySecureParametersRadioSelected(true);
            verifyView.setCustomParametersRadioVisibility(false);
            verifyView.setStandardParametersRadioVisibility(false);
          }

        });
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
    loadVerifyView("/VerifyViewCrossBenchmarkingMode.fxml",
        () -> setupVerificationObserversCrossBenchmarking(primaryStage),
        () -> {
          updateWithImportedKeyBatch(new VerifyViewUpdateOperations(verifyView));
          if (isCrossParameterBenchmarkingEnabled && this.importedKeyBatch != null) {
            verifyView.setImportKeyBatchButtonVisibility(false);
            verifyView.setCancelImportKeyButtonVisibility(true);
          }
        });

  }

  /**
   * Sets up observers specific to non-cross-benchmarking mode. This includes observers for handling
   * signature scheme changes, parameter choice changes, hash function changes, and provable scheme
   * changes.
   */
  private void setupNonCrossBenchmarkingObservers() {
    verifyView.addParameterChoiceChangeObserver(
        new ParameterChoiceChangeObserver(new VerifyViewUpdateOperations(verifyView)));
    verifyView.addHashFunctionChangeObserver(
        new HashFunctionChangeObserver(new VerifyViewUpdateOperations(verifyView)));
    verifyView.addProvableSchemeChangeObserver(
        new ProvableParamsChangeObserver(new VerifyViewUpdateOperations(verifyView)));
  }

  /**
   * Sets up observers common to all modes of the VerifyView. This includes observers for
   * benchmarking mode toggle, back to main menu actions, and other common functionalities.
   *
   * @param primaryStage The primary stage of the application where the view will be displayed.
   */
  private void setupCommonToAllObservers(Stage primaryStage) {
    verifyView.addSignatureSchemeChangeObserver(new SignatureSchemeChangeObserver());
    verifyView.addBenchmarkingModeToggleObserver(new ApplicationModeChangeObserver(
        () -> showVerifyViewStandardMode(primaryStage),
        () -> showVerifyView(primaryStage)
    ));
    verifyView.addBackToMainMenuObserver(new BackToMainMenuObserver(verifyView));
  }

  /**
   * Sets up observers specific to benchmarking mode. This includes observers for importing text
   * batches, key batches, canceling key batch import, and starting the benchmarking process.
   *
   * @param primaryStage The primary stage of the application where the view will be displayed.
   */
  private void setupBenchmarkingObservers(Stage primaryStage) {
    verifyView.addImportTextBatchBtnObserver(
        new ImportObserver(primaryStage, new VerifyViewUpdateOperations(verifyView),
            this::handleMessageBatch, "*.txt"));
    verifyView.addImportKeyBatchButtonObserver(
        new ImportObserver(primaryStage, new VerifyViewUpdateOperations(verifyView),
            this::handleKeyBatch, "*.rsa"));
    verifyView.addCancelImportKeyButtonObserver(
        new CancelImportKeyBatchButtonObserver(new VerifyViewUpdateOperations(verifyView)));
    verifyView.addCrossParameterToggleObserver(new CrossBenchmarkingModeChangeObserver(
        () -> showVerifyViewCrossBenchmarkingMode(primaryStage),
        () -> showVerifyView(primaryStage), new VerifyViewUpdateOperations(verifyView)));
    verifyView.addImportSigBatchButtonObserver(
        new ImportObserver(primaryStage, new VerifyViewUpdateOperations(verifyView),
            this::handleSignatureBatch, "*.rsa"));
    verifyView.addVerificationBenchmarkButtonObserver(
        new VerificationBenchmarkButtonObserver());
  }


  /**
   * Sets up observers for the VerifyView controls. Observers are added to handle events like text
   * import, key import, and signature scheme changes.
   *
   * @param primaryStage The stage that observers will use for file dialogs.
   */
  public void setupVerificationObserversStandard(Stage primaryStage) {
    verifyView.addImportTextObserver(
        new ImportObserver(primaryStage, new VerifyViewUpdateOperations(verifyView),
            this::handleMessageFile, "*.txt"));
    verifyView.addImportKeyObserver(
        new ImportObserver(primaryStage, new VerifyViewUpdateOperations(verifyView),
            this::handleKey, "*.rsa"));
    verifyView.addCancelImportSingleKeyButtonObserver(
        new CancelImportKeyButtonObserver(new VerifyViewUpdateOperations(verifyView)));
    verifyView.addImportSigButtonObserver(
        new ImportObserver(primaryStage, null, this::handleSig, "*.rsa"));
    verifyView.addVerifyBtnObserver(
        new VerifyBtnObserver(new VerifyViewUpdateOperations(verifyView)));
    verifyView.addCloseNotificationObserver(new BackToMainMenuObserver(verifyView));
    verifyView.addCancelImportTextButtonObserver(
        new CancelImportTextButtonObserver(new VerifyViewUpdateOperations(verifyView)));
    verifyView.addCancelImportSignatureButtonObserver(
        new CancelImportSignatureButtonObserver());
    setupNonCrossBenchmarkingObservers();
    setupCommonToAllObservers(primaryStage);
  }

  /**
   * Sets up observers for the VerifyView in benchmarking mode. This method initialises observers
   * specific to benchmarking, including text batch imports, key batch imports, benchmarking
   * initiation, and additional benchmarking-specific functionalities.
   *
   * @param primaryStage The primary stage of the application where the view will be displayed.
   */
  private void setupVerificationObserversBenchmarking(Stage primaryStage) {
    setupCommonToAllObservers(primaryStage);
    setupBenchmarkingObservers(primaryStage);
    setupNonCrossBenchmarkingObservers();
  }

  /**
   * Sets up observers for the VerifyView in cross-parameter benchmarking mode. This method
   * initialises observers specific to cross-parameter benchmarking, including standard and provable
   * hash function changes, and other functionalities specific to this mode.
   *
   * @param primaryStage The primary stage of the application where the view will be displayed.
   */
  private void setupVerificationObserversCrossBenchmarking(Stage primaryStage) {
    setupCommonToAllObservers(primaryStage);
    setupBenchmarkingObservers(primaryStage);
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
      if (!setHashSizeInModel(new VerifyViewUpdateOperations(verifyView))) {
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
   * Observer for initiating the signature verification benchmark. Handles the event triggered for
   * starting the benchmarking process, sets up the task, and shows the progress on the UI.
   */
  class VerificationBenchmarkButtonObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
      hashOutputSize = verifyView.getHashOutputSize();
      if (signatureModel.getNumTrials() * signatureModel.getPublicKeyBatchLength()
          != numSignatures) {
        uk.msci.project.rsa.DisplayUtility.showErrorAlert(
            "The numbers of messages and signatures do not match. Please ensure they match for a valid set of verification pairings.");
        return;
      }
      if (isCrossParameterBenchmarkingEnabled) {
        handleBenchmarkingInitiationComparisonMode();
        return;
      }

      if ((signatureModel.getNumTrials() == 0)
          || signatureModel.getPublicKeyBatchLength() == 0
          || signatureModel.getSignatureType() == null || numSignatures == 0
          || signatureModel.getHashType() == null) {
        uk.msci.project.rsa.DisplayUtility.showErrorAlert(
            "You must provide an input for all fields. Please try again.");
        return;
      }

      if (!setHashSizeInModel(new VerifyViewUpdateOperations(verifyView))) {
        return;
      }
      // Show the progress dialog
      benchmarkingUtility = new BenchmarkingUtility();
      Task<Void> benchmarkingTask = createBenchmarkingTask(messageBatchFile, signatureBatchFile);
      BenchmarkingUtility.beginBenchmarkWithUtility(benchmarkingUtility, "Signature Verification",
          benchmarkingTask,
          SignatureVerificationController.this::handleBenchmarkingCompletion,
          mainController.getPrimaryStage());
    }
  }

  /**
   * Handles the initiation of the benchmarking process in comparison mode. This method checks for
   * required inputs specific to comparison mode benchmarking and initiates the benchmarking task.
   * It sets up the progress dialog and begins the task for generating signatures across different
   * key sizes and parameter settings, providing feedback on the progress to the user.
   */
  private void handleBenchmarkingInitiationComparisonMode() {

    if ((signatureModel.getNumTrials() == 0)
        || signatureModel.getPublicKeyBatchLength() == 0
        || signatureModel.getSignatureType() == null || numSignatures == 0
        || signatureModel.getCurrentFixedHashType_ComparisonMode() == null
        || signatureModel.getCurrentProvableHashType_ComparisonMode() == null) {
      uk.msci.project.rsa.DisplayUtility.showErrorAlert(
          "You must provide an input for all fields. Please try again.");
      return;
    }

    if (!setHashSizeInModel(new VerifyViewUpdateOperations(verifyView))) {
      return;
    }
    benchmarkingUtility = new BenchmarkingUtility();
    Task<Void> benchmarkingTask = createBenchmarkingTaskComparisonMode(messageBatchFile,
        signatureBatchFile);
    BenchmarkingUtility.beginBenchmarkWithUtility(benchmarkingUtility, "Signature Verification",
        benchmarkingTask,
        SignatureVerificationController.this::handleBenchmarkingCompletionComparisonMode,
        mainController.getPrimaryStage());
  }

  /**
   * Creates a task for benchmarking signature verification in comparison mode. This task involves
   * verifying a batch of signatures across different key sizes and parameter settings. The task
   * updates the progress of verification to the user.
   *
   * @param messageFile        The file containing a batch of messages to be verified.
   * @param batchSignatureFile The file containing a batch of signatures corresponding to the
   *                           messages.
   * @return A Task<Void> that will execute the benchmarking process in the background.
   */
  private Task<Void> createBenchmarkingTaskComparisonMode(File messageFile,
      File batchSignatureFile) {
    return new Task<>() {
      @Override
      protected Void call() throws Exception {
        signatureModel.batchVerifySignatures_ComparisonMode(messageFile, batchSignatureFile,
            progress -> Platform.runLater(() -> {
              benchmarkingUtility.updateProgress(progress);
              benchmarkingUtility.updateProgressLabel(String.format("%.0f%%", progress * 100));
            }));
        return null;
      }
    };

  }

  /**
   * Creates a task for benchmarking the signature verification process. This task verifies a batch
   * of signatures against a batch of messages and updates the progress on the UI. It is used in
   * standard benchmarking mode.
   *
   * @param messageFile        The file containing a batch of messages to be verified.
   * @param batchSignatureFile The file containing a batch of signatures corresponding to the
   *                           messages.
   * @return A Task<Void> that will execute the benchmarking process in the background.
   */
  private Task<Void> createBenchmarkingTask(File messageFile, File batchSignatureFile) {
    return new Task<>() {
      @Override
      protected Void call() throws Exception {
        signatureModel.batchVerifySignatures(messageFile, batchSignatureFile,
            progress -> Platform.runLater(() -> {
              benchmarkingUtility.updateProgress(progress);
              benchmarkingUtility.updateProgressLabel(String.format("%.0f%%", progress * 100));
            }));
        return null;
      }
    };

  }

  /**
   * Handles the completion of the benchmarking task in comparison mode. This method is called when
   * the benchmarking task successfully completes in the context of cross-parameter benchmarking. It
   * resets the pre-loaded key parameters, initialises the ResultsController with the appropriate
   * context, and displays the results view with the gathered benchmarking data. This method is
   * pivotal in finalising the benchmarking process and presenting the results to the user.
   */
  private void handleBenchmarkingCompletionComparisonMode() {
    resetPreLoadedKeyParams();
    ResultsController resultsController = new ResultsController(mainController);
    BenchmarkingContext context = new SignatureVerificationContext(signatureModel);
    resultsController.setContext(context);

    resultsController.showResultsView(mainController.getPrimaryStage(),
        signatureModel.getClockTimesPerTrial(), signatureModel.getPublicKeyLengths(), true,
        signatureModel.getNumKeySizesForComparisonMode());
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
      verifyView.setCancelImportTextBatchButtonVisibility(false);
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
