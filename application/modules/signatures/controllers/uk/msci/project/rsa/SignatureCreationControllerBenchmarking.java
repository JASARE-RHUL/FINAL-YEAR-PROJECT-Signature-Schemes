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
 * responsible for handling user interactions for the signature creation process. It also
 * communicates with the Signature Model to perform the actual signature creation logic.
 */
public class SignatureCreationControllerBenchmarking extends
    AbstractSignatureBaseControllerBenchmarking {

  /**
   * The view component of the MVC pattern for the signing functionality. It handles the user
   * interface for the digital signature generation.
   */
  private SignView signView;


  /**
   * An instance of the BenchmarkingUtility class used to manage benchmarking tasks. This utility
   * facilitates the execution and monitoring of tasks related to the benchmarking of signature
   * creation processes. It provides methods to initiate benchmarking tasks, update progress, and
   * handle task completion.
   */
  private BenchmarkingUtility benchmarkingUtility;


  /**
   * Constructs a SignatureCreationController with a reference to the MainController to be used in
   * the event of the user initiating a switch back to main menu.
   *
   * @param mainController The main controller that this controller is part of.
   */
  public SignatureCreationControllerBenchmarking(MainController mainController) {
    super(mainController);
  }

  /**
   * Transitions the user interface to the standard mode of signature creation. This method is
   * responsible for loading and displaying the standard mode view of the signature creation
   * process, to be used when benchmarking features are not required.
   *
   * @param primaryStage The primary stage of the application where the view will be displayed.
   */
  @Override
  public void showStandardMode(Stage primaryStage) {
    mainController.showSignatureCreationStandard();
  }

  /**
   * Loads the SignView FXML corresponding to a mode for the sign view (e.g., standard,
   * benchmarking, cross benchmarking) and initialises the view. This method handles the setup for
   * different SignView modes based on the provided FXML path and runs the observer setup and
   * additional setup based on mode.
   *
   * @param fxmlPath                   Path to the FXML file to load.
   * @param observerSetup              Runnable containing the observer setup logic.
   * @param additionalSetupBasedOnMode Runnable containing additional setup logic specific to the
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
   * Displays the SignView interface. This method decides which version of the SignView to show
   * based on the current benchmarking and cross-parameter modes. If cross-parameter benchmarking is
   * enabled, it calls {@code showSignViewCrossBenchmarkingMode}. Otherwise, it loads the normal
   * benchmarking SignView. This method is responsible for setting up the SignView with the
   * necessary controllers and observers.
   *
   * @param primaryStage The primary stage of the application where the view will be displayed.
   */
  public void showBenchmarkingView(Stage primaryStage) {
    isBenchmarkingMode = true;
    if (isKeyForComparisonMode && isCrossParameterBenchmarkingEnabled) {
      showCrossBenchmarkingView(primaryStage);
      return;
    }
    loadSignView("/SignView.fxml", () -> {
          this.signatureModelBenchmarking = new SignatureModelBenchmarking();
          setupObserversBenchmarkingMode(primaryStage, signView, signatureModelBenchmarking);
        },
        () -> {
          preloadProvablySecureKeyBatch(signView, signatureModelBenchmarking);
        });
  }


  /**
   * Displays the SignView in cross-parameter benchmarking mode. This method loads the SignView
   * specifically configured for cross-parameter benchmarking. It initialises the view, sets up the
   * necessary observers for handling key and message batch imports, and displays the view on the
   * provided stage.
   *
   * @param primaryStage The primary stage of the application where the view will be displayed.
   */
  public void showCrossBenchmarkingView(Stage primaryStage) {
    loadSignView("/SignViewCrossBenchmarkingMode.fxml",
        () -> {
          this.signatureModelComparisonBenchmarking = new SignatureModelComparisonBenchmarking();
          setupObserversCrossBenchmarking(primaryStage, signView,
              signatureModelComparisonBenchmarking);
        },
        () -> {
          preloadCrossParameterKeyBatch(signView);
          preloadCustomCrossParameterHashFunctions(signView);
        });
  }

  /**
   * Sets up observers specific to benchmarking mode in the context of signature creation. This
   * includes observers for importing text batches, key batches, cancelling key batch import, and
   * starting the benchmarking process. These observers are essential for enabling the interactions
   * required for the effective benchmarking of signature creation processes.
   *
   * @param primaryStage               The primary stage of the application where the view will be
   *                                   displayed.
   * @param signatureView              The signature view associated with this controller.
   * @param signatureModelBenchmarking The benchmarking model used for signature creation
   *                                   processes.
   */
  @Override
  void setupBenchmarkingObservers(Stage primaryStage, SignatureBaseView signatureView,
      AbstractSignatureModelBenchmarking signatureModelBenchmarking) {
    super.setupBenchmarkingObservers(primaryStage, signView, signatureModelBenchmarking);
    signView.addSigBenchmarkButtonObserver(
        new SignatureBenchmarkObserver());
  }


  /**
   * Observer for initiating the signature generation benchmark. This class handles the event
   * triggered for starting the benchmarking process. Depending on the benchmarking mode, it either
   * initiates a standard benchmarking task or calls 'handleBenchmarkingInitiationComparisonMode'
   * for comparison mode benchmarking. It ensures the necessary preconditions are met, sets up the
   * task, and manages the progress display on the UI.
   */
  class SignatureBenchmarkObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
      hashOutputSize = signView.getHashOutputSizeArea();

      if (isCrossParameterBenchmarkingEnabled) {
        handleBenchmarkingInitiationComparisonMode();
        return;
      }

      if ((signatureModelBenchmarking.getNumTrials() == 0)
          || signatureModelBenchmarking.getKeyBatchLength() == 0
          || signatureModelBenchmarking.getSignatureType() == null
          || signatureModelBenchmarking.getHashType() == null) {
        uk.msci.project.rsa.DisplayUtility.showErrorAlert(
            "You must provide an input for all fields. Please try again.");
        return;
      }

      if (!setHashSizeInModelBenchmarking(signView)) {
        return;
      }
      benchmarkingUtility = new BenchmarkingUtility();
      Task<Void> benchmarkingTask = createBenchmarkingTask(messageBatchFile);
      BenchmarkingUtility.beginBenchmarkWithUtility(benchmarkingUtility, "Signature Generation",
          benchmarkingTask,
          SignatureCreationControllerBenchmarking.this::handleBenchmarkingCompletion,
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
        || signatureModelComparisonBenchmarking.getSignatureType() == null
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

    if (!setHashSizeInModelBenchmarking(signView) && !isCustomCrossParameterBenchmarkingMode) {
      return;
    }
    if (!isCustomCrossParameterBenchmarkingMode) {
      signatureModelComparisonBenchmarking.createDefaultKeyConfigToHashFunctionsMap();
    }
    benchmarkingUtility = new BenchmarkingUtility();
    Task<Void> benchmarkingTask = createBenchmarkingTaskComparisonMode(messageBatchFile);
    BenchmarkingUtility.beginBenchmarkWithUtility(benchmarkingUtility, "Signature Generation",
        benchmarkingTask,
        SignatureCreationControllerBenchmarking.this::handleBenchmarkingCompletionComparisonMode,
        mainController.getPrimaryStage());
  }

  /**
   * Creates a benchmarking task for signature generation. This task is responsible for processing a
   * batch of messages, generating signatures, and updating the UI with progress.
   *
   * @param messageFile The file containing the messages to be signed.
   * @return The task to be executed for benchmarking.
   */
  private Task<Void> createBenchmarkingTask(File messageFile) {
    return new Task<>() {
      @Override
      protected Void call() throws Exception {
        signatureModelBenchmarking.batchCreateSignatures(messageFile,
            progress -> Platform.runLater(() -> {
              benchmarkingUtility.updateProgress(progress);
              benchmarkingUtility.updateProgressLabel(String.format("%.0f%%", progress * 100));
            }));
        return null;
      }
    };

  }

  /**
   * Creates a benchmarking task for signature generation in comparison mode. This task is
   * responsible for processing a batch of messages, generating signatures, and updating the UI with
   * progress.
   *
   * @param messageFile The file containing the messages to be signed.
   * @return The task to be executed for benchmarking.
   */
  private Task<Void> createBenchmarkingTaskComparisonMode(File messageFile) {
    return new Task<>() {
      @Override
      protected Void call() throws Exception {
        signatureModelComparisonBenchmarking.batchCreateSignatures(messageFile,
            progress -> Platform.runLater(() -> {
              benchmarkingUtility.updateProgress(progress);
              benchmarkingUtility.updateProgressLabel(String.format("%.0f%%", progress * 100));
            }));
        return null;
      }
    };

  }

  /**
   * Handles the completion of the benchmarking task for signature creation. This method is called
   * when the benchmarking task successfully completes. It initialises and sets up the
   * ResultsController with the appropriate context (SignatureCreationContext) and displays the
   * results view with the gathered benchmarking data.
   */
  private void handleBenchmarkingCompletion() {
    resetPreLoadedKeyParams();
    ResultsControllerNormalBenchmarking resultsController = new ResultsControllerNormalBenchmarking(
        mainController);
    BenchmarkingContext context = new SignatureCreationContext(signatureModelBenchmarking);
    resultsController.setContext(context);
    resultsController.showResultsView(null,
        signatureModelBenchmarking.getClockTimesPerTrial(),
        signatureModelBenchmarking.getKeyLengths(), false, 0);
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
    ResultsControllerComparisonBenchmarking resultsController = new ResultsControllerComparisonBenchmarking(
        mainController);
    BenchmarkingContext context = new SignatureCreationContext(
        signatureModelComparisonBenchmarking);
    resultsController.setContext(context);

    resultsController.showResultsView(keyConfigurationStrings,
        signatureModelComparisonBenchmarking.getClockTimesPerTrial(),
        signatureModelComparisonBenchmarking.getKeyLengths(), true,
        signatureModelComparisonBenchmarking.getNumKeySizesForComparisonMode());
  }


  /**
   * Handles the process of importing a batch of messages for signature creation in the benchmarking
   * mode. This method validates the file's content and updates the model and UI accordingly. It
   * ensures the file format is correct and contains the expected number of messages, facilitating
   * batch operations in benchmarking scenarios.
   *
   * @param file           The file containing a batch of messages for signature creation.
   * @param signatureView  The signature view associated with this controller.
   * @param signatureModel The benchmarking model used for processing the message batch.
   */
  public void handleMessageBatch(File file, SignatureBaseView signatureView,
      AbstractSignatureModelBenchmarking signatureModel) {
    int numMessages = checkFileForNonEmptyLines(file, "message");
    try {
      if (numMessages > 0) {
        this.messageBatchFile = file;

        if (numMessages != Integer.parseInt(signView.getNumMessageField())) {
          uk.msci.project.rsa.DisplayUtility.showErrorAlert(
              "Message batch could not be imported. Please ensure the number "
                  + "of messages contained in the file matches the number of messages "
                  + "entered in the above field");
          return;
        } else {
          signatureModel.setNumTrials(numMessages);
          signatureView.setMessageBatch(file.getName());
          signatureView.setTextFileCheckmarkImage();
          signatureView.setTextFieldCheckmarkImageVisibility(true);
          signatureView.setMessageBatchFieldVisibility(true);
          signatureView.setNumMessageFieldEditable(false);
          signatureView.setImportTextBatchBtnVisibility(false);
          signatureView.setCancelImportTextBatchButtonVisibility(true);
          signatureView.addCancelImportTextBatchButtonObserver(
              new CancelImportTextBatchButtonObserver());
        }
      }
    } catch (NumberFormatException e) {
      uk.msci.project.rsa.DisplayUtility.showErrorAlert(
          "Message batch could not be imported. Please ensure the number "
              + "of messages contained in the file matches the number of messages "
              + "entered in the above field");
    }
  }


  /**
   * Observer for canceling the import of a text batch. Handles the event when the user decides to
   * cancel the import of a batch of messages by replacing the cancel button with the original
   * import button and resetting corresponding text field that display the name of the file.
   */
  class CancelImportTextBatchButtonObserver implements EventHandler<ActionEvent> {


    @Override
    public void handle(ActionEvent event) {
      signView.setTextFieldCheckmarkImageVisibility(false);
      signView.setMessageBatch("Please Import a message batch");
      signView.clearNumMessageField();
      signatureModelBenchmarking.setNumTrials(0);
      messageBatchFile = null;
      signView.setImportTextBatchBtnVisibility(true);
      signView.setCancelImportTextBatchButtonVisibility(false);
    }
  }


}