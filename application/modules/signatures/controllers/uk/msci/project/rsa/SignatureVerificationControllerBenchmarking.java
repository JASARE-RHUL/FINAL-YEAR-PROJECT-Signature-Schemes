package uk.msci.project.rsa;

import java.io.File;
import java.io.IOException;
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
public class SignatureVerificationControllerBenchmarking extends
    AbstractSignatureBaseControllerBenchmarking {

  /**
   * The view component of the MVC pattern for the verification functionality. It handles the user
   * interface for the digital signature verification.
   */
  private VerifyView verifyView;

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
  public SignatureVerificationControllerBenchmarking(MainController mainController) {
    super(mainController);
  }

  @Override
  public void showStandardMode(Stage primaryStage) {
    mainController.showSignatureVerificationStandard();
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
   * Initialises and displays the VerifyView in benchmarking mode. This method loads the FXML for
   * the VerifyView, sets up the user interface scene, and configures the stage for the
   * application.
   *
   * @param primaryStage The primary stage for this application upon which the standard mode
   *                     verification view will be set. This stage is used as the main window for
   *                     the application.
   */
  public void showBenchmarkingView(Stage primaryStage) {
    isBenchmarkingMode = true;
    if (isKeyForComparisonMode && isCrossParameterBenchmarkingEnabled) {
      showCrossBenchmarkingView(primaryStage);
      return;
    }
    loadVerifyView("/VerifyView.fxml",
        () -> {
          this.signatureModelBenchmarking = new SignatureModelBenchmarking();
          setupObserversBenchmarkingMode(primaryStage, verifyView, signatureModelBenchmarking);
        },
        () -> preloadProvablySecureKeyBatch(verifyView, signatureModelBenchmarking));
  }


  /**
   * Displays the VerifyView in cross-parameter benchmarking mode. This method loads the VerifyView
   * specifically configured for cross-parameter benchmarking. It initialises the view, sets up the
   * necessary observers for handling key and message batch imports, and displays the view on the
   * provided stage.
   *
   * @param primaryStage The primary stage of the application where the view will be displayed.
   */
  public void showCrossBenchmarkingView(Stage primaryStage) {
    loadVerifyView("/VerifyViewCrossBenchmarkingMode.fxml",
        () -> {
          this.signatureModelComparisonBenchmarking = new SignatureModelComparisonBenchmarking();
          setupObserversCrossBenchmarking(primaryStage, verifyView,
              signatureModelComparisonBenchmarking);
        },
        () -> {
          preloadCrossParameterKeyBatch(verifyView);
          preloadCustomCrossParameterHashFunctions(verifyView);
        });
  }


  /**
   * Sets up observers specific to benchmarking mode for signature verification. This method
   * includes observers for actions such as importing message and signature batches, canceling
   * imports, and initiating the benchmarking process. These observers facilitate the user
   * interactions required for the effective benchmarking of signature verification processes in
   * various benchmarking scenarios.
   *
   * @param primaryStage               The primary stage of the application where the view will be
   *                                   displayed.
   * @param signatureView              The signature view associated with this controller.
   * @param signatureModelBenchmarking The benchmarking model used for signature verification
   *                                   processes.
   */
  @Override
  void setupBenchmarkingObservers(Stage primaryStage, SignatureBaseView signatureView,
      AbstractSignatureModelBenchmarking signatureModelBenchmarking) {
    super.setupBenchmarkingObservers(primaryStage, verifyView, signatureModelBenchmarking);
    verifyView.addImportSigBatchButtonObserver(
        new ImportObserver(primaryStage, verifyView, null,
            this::handleSignatureBatch, "*.rsa"));
    verifyView.addVerificationBenchmarkButtonObserver(
        new VerificationBenchmarkButtonObserver(signatureModelBenchmarking));
  }


  /**
   * Observer for initiating the signature verification benchmark. Handles the event triggered for
   * starting the benchmarking process, sets up the task, and shows the progress on the UI.
   */
  class VerificationBenchmarkButtonObserver implements EventHandler<ActionEvent> {

    private AbstractSignatureModelBenchmarking signatureModelBenchmarking;

    public VerificationBenchmarkButtonObserver(
        AbstractSignatureModelBenchmarking signatureModelBenchmarking) {
      this.signatureModelBenchmarking = signatureModelBenchmarking;
    }

    @Override
    public void handle(ActionEvent event) {
      hashOutputSize = verifyView.getHashOutputSizeArea();
      if (signatureModelBenchmarking.getNumTrials() * signatureModelBenchmarking.getKeyBatchLength()
          != numSignatures) {
        uk.msci.project.rsa.DisplayUtility.showErrorAlert(
            "The numbers of messages and signatures do not match. Please ensure they match for a valid set of verification pairings.");
        return;
      }
      if (isCrossParameterBenchmarkingEnabled) {
        handleBenchmarkingInitiationComparisonMode();
        return;
      }

      if ((signatureModelBenchmarking.getNumTrials() == 0)
          || signatureModelBenchmarking.getKeyBatchLength() == 0
          || signatureModel.getSignatureType() == null || numSignatures == 0
          || signatureModel.getHashType() == null) {
        uk.msci.project.rsa.DisplayUtility.showErrorAlert(
            "You must provide an input for all fields. Please try again.");
        return;
      }

      if (!setHashSizeInModelBenchmarking(verifyView)) {
        return;
      }
      // Show the progress dialog
      benchmarkingUtility = new BenchmarkingUtility();
      Task<Void> benchmarkingTask = createBenchmarkingTask(messageBatchFile, signatureBatchFile);
      BenchmarkingUtility.beginBenchmarkWithUtility(benchmarkingUtility, "Signature Verification",
          benchmarkingTask,
          SignatureVerificationControllerBenchmarking.this::handleBenchmarkingCompletion,
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

    if ((signatureModelComparisonBenchmarking.getNumTrials() == 0)
        || signatureModelComparisonBenchmarking.getKeyBatchLength() == 0
        || signatureModelComparisonBenchmarking.getSignatureType() == null || numSignatures == 0
        || (signatureModelComparisonBenchmarking.getCurrentFixedHashTypeList_ComparisonMode().size()
        == 0
        && !isCustomCrossParameterBenchmarkingMode)
        ||
        signatureModelComparisonBenchmarking.getCurrentProvableHashTypeList_ComparisonMode().size()
            == 0
            && !isCustomCrossParameterBenchmarkingMode) {
      uk.msci.project.rsa.DisplayUtility.showErrorAlert(
          "You must provide an input for all fields. Please try again.");
      return;
    }

    if (!setHashSizeInModelBenchmarking(verifyView)) {
      return;
    }
    if (!isCustomCrossParameterBenchmarkingMode) {
      signatureModelComparisonBenchmarking.createDefaultKeyConfigToHashFunctionsMap();
    }
    benchmarkingUtility = new BenchmarkingUtility();
    Task<Void> benchmarkingTask = createBenchmarkingTaskComparisonMode(messageBatchFile,
        signatureBatchFile);
    BenchmarkingUtility.beginBenchmarkWithUtility(benchmarkingUtility, "Signature Verification",
        benchmarkingTask,
        SignatureVerificationControllerBenchmarking.this::handleBenchmarkingCompletionComparisonMode,
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
        signatureModelBenchmarking.batchVerifySignatures(messageFile, batchSignatureFile,
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
        signatureModelBenchmarking.batchVerifySignatures(messageFile, batchSignatureFile,
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
    BenchmarkingContext context = new SignatureVerificationContext(
        signatureModelComparisonBenchmarking);
    resultsController.setContext(context);

    resultsController.showResultsView(mainController.getPrimaryStage(), keyConfigurationStrings,
        signatureModelComparisonBenchmarking.getClockTimesPerTrial(),
        signatureModelComparisonBenchmarking.getKeyLengths(), true,
        signatureModelComparisonBenchmarking.getNumKeySizesForComparisonMode());
  }


  /**
   * Handles the completion of the benchmarking task for signature verification. This method is
   * called when the benchmarking task successfully completes. It initialises and sets up the
   * ResultsController with the appropriate context (SignatureVerificationContext) and displays the
   * results view with the gathered benchmarking data.
   */
  private void handleBenchmarkingCompletion() {
    ResultsController resultsController = new ResultsController(mainController);
    BenchmarkingContext context = new SignatureVerificationContext(signatureModelBenchmarking);
    resultsController.setContext(context);
    resultsController.showResultsView(mainController.getPrimaryStage(),
        signatureModelBenchmarking.getClockTimesPerTrial(),
        signatureModelBenchmarking.getKeyLengths());
  }

  /**
   * Observer for canceling the import of a text batch. Handles the event when the user decides to
   * cancel the import of a batch of messages by replacing the cancel button with the original
   * import button and resetting corresponding text field that display the name of the file.
   */
  class CancelImportTextBatchButtonObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
      verifyView.setTextFieldCheckmarkImageVisibility(false);
      verifyView.setMessageBatch("Please Import a message batch");
      messageBatchFile = null;
      verifyView.setCancelImportTextBatchButtonVisibility(false);
      verifyView.setImportTextBatchBtnVisibility(true);

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
   * Handles the processing of a file containing a batch of messages for signature verification in
   * benchmarking mode. This method validates the content of the file and updates the model and UI
   * accordingly. It ensures the file format is correct and contains a valid batch of messages,
   * facilitating batch operations in the verification benchmarking scenario.
   *
   * @param file                       The file containing a batch of messages for signature
   *                                   verification.
   * @param signatureView              The signature view associated with this controller.
   * @param signatureModelBenchmarking The benchmarking model used for processing the message
   *                                   batch.
   */
  public void handleMessageBatch(File file, SignatureBaseView signatureView,
      AbstractSignatureModelBenchmarking signatureModelBenchmarking) {
    int numTrials = checkFileForNonEmptyLines(file, "message");
    if (numTrials > 0) {
      messageBatchFile = file;
      signatureModelBenchmarking.setNumTrials(numTrials);
      verifyView.setMessageBatch(file.getName());
      verifyView.setTextFileCheckmarkImage();
      verifyView.setTextFieldCheckmarkImageVisibility(true);
      verifyView.setMessageBatchFieldVisibility(true);
      verifyView.setImportTextBatchBtnVisibility(false);
      verifyView.setCancelImportTextBatchButtonVisibility(true);
      verifyView.addCancelImportTextBatchButtonObserver(
          new CancelImportTextBatchButtonObserver());
    }
  }


  /**
   * Processes a file containing a batch of signatures for signature verification. Validates
   * the file's content and updates the model and UI accordingly. Ensures the file format is
   * correct and contains a valid batch of signatures. This method is essential for handling
   * batch operations in signature verification benchmarking scenarios.
   *
   * @param file The file containing a batch of signatures for verification.
   * @param signatureView The signature view to be updated with the imported signature batch.
   * @param signatureModelBenchmarking The benchmarking model used for processing the signature batch.
   */
  public void handleSignatureBatch(File file, SignatureBaseView signatureView,
      AbstractSignatureModelBenchmarking signatureModelBenchmarking) {
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

}
