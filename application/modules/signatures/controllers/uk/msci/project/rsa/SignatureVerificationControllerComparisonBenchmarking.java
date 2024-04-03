package uk.msci.project.rsa;

import javafx.application.Platform;
import javafx.concurrent.Task;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.stage.Stage;


/**
 * This class extends the AbstractSignatureCreationControllerBenchmarking to provide specialised
 * functionalities for signature verification in cross-parameter benchmarking mode. This class is
 * pivotal in managing the process of comparing signature schemes' performance across various key
 * sizes and configurations.
 */
public class SignatureVerificationControllerComparisonBenchmarking extends
    SignatureVerificationControllerBenchmarking {


  /**
   * The SignatureModelComparisonBenchmarking component in the MVC pattern. It handles the data and
   * business logic specific to cross-parameter benchmarking mode in digital signature operations.
   * This model supports comparing the performance and behavior of different signature schemes
   * across varying parameters and configurations.
   */
  SignatureModelComparisonBenchmarking signatureModel;


  /**
   * Constructs a SignatureCreationController with a reference to the MainController to be used in
   * the event of the user initiating a switch back to main menu.
   *
   * @param mainController The main controller that this controller is part of.
   */
  public SignatureVerificationControllerComparisonBenchmarking(MainController mainController) {
    super(mainController);
  }


  /**
   * Displays the VerifyView in cross-parameter benchmarking mode. This method loads the VerifyView
   * specifically configured for cross-parameter benchmarking. It initialises the view, sets up the
   * necessary observers for handling key and message batch imports, and displays the view on the
   * provided stage.
   *
   * @param primaryStage The primary stage of the application where the view will be displayed.
   */
  @Override
  public void showCrossBenchmarkingView(Stage primaryStage) {
    if ((isCrossParameterBenchmarkingEnabled && importedKeyBatch == null)
        || !isKeyForComparisonMode) {
      throw new IllegalStateException(
          "Cross parameter benchmarking cannot be enabled without an initial cross parameter generation of keys.");
    }
    loadVerifyView("/VerifyViewCrossBenchmarkingMode.fxml",
        () -> {
          this.signatureModel = new SignatureModelComparisonBenchmarking();
          setupObserversCrossBenchmarking(primaryStage, verifyView,
              signatureModel);
        },
        () -> {
          preloadCrossParameterKeyBatch(verifyView, signatureModel);
          preloadCustomCrossParameterHashFunctions(verifyView,
              signatureModel);
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
        new VerificationBenchmarkButtonObserver(signatureModel));
  }


  /**
   * Observer for initiating the signature verification benchmark. Handles the event triggered for
   * starting the benchmarking process, sets up the task, and shows the progress on the UI.
   */
  class VerificationBenchmarkButtonObserver implements EventHandler<ActionEvent> {

    private SignatureModelComparisonBenchmarking signatureModel;

    public VerificationBenchmarkButtonObserver(
        SignatureModelComparisonBenchmarking signatureModel) {
      this.signatureModel = signatureModel;
    }

    @Override
    public void handle(ActionEvent event) {
      hashOutputSize = verifyView.getHashOutputSizeArea();
      if ((signatureModel.getNumTrials() == 0)
          || signatureModel.getKeyBatchLength() == 0
          || signatureModel.getSignatureType() == null || numSignatures == 0
          || (signatureModel.getCurrentFixedHashTypeList_ComparisonMode()
          .isEmpty()
          && !isCustomCrossParameterBenchmarkingMode)
          ||
          signatureModel.getCurrentProvableHashTypeList_ComparisonMode()
              .isEmpty()
              && !isCustomCrossParameterBenchmarkingMode) {
        uk.msci.project.rsa.DisplayUtility.showErrorAlert(
            "You must provide an input for all fields. Please try again.");
        return;
      }
      if (!isCustomCrossParameterBenchmarkingMode) {
        signatureModel.createDefaultKeyConfigToHashFunctionsMap();
      }


      benchmarkingUtility = new BenchmarkingUtility();
      Task<Void> benchmarkingTask = null;
      if (signatureModel.getRecoveryStatus()) {
        if (((numTrials
            != numSignatures) || ((numSignatures % (signatureModel.calculateNumBenchmarkingRuns()
            * signatureModel.getNumKeySizesForComparisonMode())) != 0))) {
          uk.msci.project.rsa.DisplayUtility.showErrorAlert(
              "Your selected combination of signature, non recoverable message batch and "
                  + "hash function selections do not match. Please ensure they match to proceed.");
          return;
        }
     benchmarkingTask = new Task<Void>() {
          @Override
          protected Void call() throws Exception {
            signatureModel.batchVerifySignaturesForRecovery(messageBatchFile, signatureBatchFile,
                progress -> Platform.runLater(() -> {
                  benchmarkingUtility.updateProgress(progress);
                  benchmarkingUtility.updateProgressLabel(String.format("%.0f%%", progress * 100));
                }));
            return null;
          }
        };
      } else {
        if (((signatureModel.calculateNumBenchmarkingRuns() * numTrials
            * signatureModel.getNumKeySizesForComparisonMode()) != numSignatures)) {
          uk.msci.project.rsa.DisplayUtility.showErrorAlert(
              "The signature-message batches and your chosen hash function selections do not match. Please ensure they match to proceed.");
          return;
        }
        benchmarkingTask = createBenchmarkingTask(messageBatchFile,
            signatureBatchFile, signatureModel);
      }

      if (!setHashSizeInModelBenchmarking(verifyView, signatureModel)) {
        return;
      }

      BenchmarkingUtility.beginBenchmarkWithUtility(benchmarkingUtility, "Signature Verification",
          benchmarkingTask,
          SignatureVerificationControllerComparisonBenchmarking.this::handleBenchmarkingCompletion,
          mainController.getPrimaryStage());

    }
  }


  /**
   * Handles the completion of the benchmarking task in comparison mode. This method is called when
   * the benchmarking task successfully completes in the context of cross-parameter benchmarking. It
   * resets the pre-loaded key parameters, initialises the ResultsController with the appropriate
   * context, and displays the results view with the gathered benchmarking data. This method is
   * pivotal in finalising the benchmarking process and presenting the results to the user.
   */
  @Override
  void handleBenchmarkingCompletion() {
    resetPreLoadedKeyParams();
    ResultsControllerComparisonBenchmarking resultsController = new ResultsControllerComparisonBenchmarking(
        mainController);
    BenchmarkingContext context = new SignatureVerificationContext(
        signatureModel);
    resultsController.setContext(context);
    resultsController.showResultsView(keyConfigurationStrings,
        signatureModel.getClockTimesPerTrial(),
        signatureModel.getKeyLengths(), true,
        signatureModel.getNumKeySizesForComparisonMode());
  }


}
