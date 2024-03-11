package uk.msci.project.rsa;

import javafx.concurrent.Task;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.stage.Stage;
import uk.msci.project.rsa.SignatureCreationControllerBenchmarking.SignatureBenchmarkObserver;


/**
 * This class extends the AbstractSignatureCreationControllerBenchmarking to provide specialised
 * functionalities for signature creation in cross-parameter benchmarking mode. This class is
 * pivotal in managing the process of comparing signature schemes' performance across various key
 * sizes and configurations.
 */
public class SignatureCreationControllerComparisonBenchmarking extends
    AbstractSignatureCreationControllerBenchmarking {


  /**
   * The SignatureModelComparisonBenchmarking component in the MVC pattern. It handles the data and
   * business logic specific to cross-parameter benchmarking mode in digital signature operations.
   * This model supports comparing the performance and behavior of different signature schemes
   * across varying parameters and configurations.
   */
  SignatureModelComparisonBenchmarking signatureModelComparisonBenchmarking;


  /**
   * Constructs a SignatureCreationController with a reference to the MainController to be used in
   * the event of the user initiating a switch back to main menu.
   *
   * @param mainController The main controller that this controller is part of.
   */
  public SignatureCreationControllerComparisonBenchmarking(MainController mainController) {
    super(mainController);
  }


  /**
   * Displays the SignView in cross-parameter benchmarking mode. This method loads the SignView
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
    } else {

      loadSignView("/SignViewCrossBenchmarkingMode.fxml",
          () -> {
            this.signatureModelComparisonBenchmarking = new SignatureModelComparisonBenchmarking();
            setupObserversCrossBenchmarking(primaryStage, signView,
                signatureModelComparisonBenchmarking);
          },
          () -> {
            preloadCrossParameterKeyBatch(signView, signatureModelComparisonBenchmarking);
            preloadCustomCrossParameterHashFunctions(signView,
                signatureModelComparisonBenchmarking);
          });
    }
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
    signView.addSigBenchmarkButtonObserver(new SignatureBenchmarkObserver());
  }


  /**
   * Observer for initiating the signature generation benchmark in comparison mode. This class
   * handles the event triggered for starting the benchmarking process. Handles the initiation of
   * the benchmarking process in comparison mode. This method checks for required inputs specific to
   * comparison mode benchmarking and initiates the benchmarking task. It sets up the progress
   * dialog and begins the task for generating signatures across different key sizes and parameter
   * settings, providing feedback on the progress to the user.
   */

  class SignatureBenchmarkObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
      hashOutputSize = signView.getHashOutputSizeArea();

      if ((signatureModelComparisonBenchmarking.getNumTrials() == 0)
          || signatureModelComparisonBenchmarking.getKeyBatchLength() == 0
          || signatureModelComparisonBenchmarking.getSignatureType() == null
          || (signatureModelComparisonBenchmarking.getCurrentFixedHashTypeList_ComparisonMode()
          .isEmpty()
          && !isCustomCrossParameterBenchmarkingMode)
          ||
          signatureModelComparisonBenchmarking.getCurrentProvableHashTypeList_ComparisonMode()
              .isEmpty()
              && !isCustomCrossParameterBenchmarkingMode) {
        uk.msci.project.rsa.DisplayUtility.showErrorAlert(
            "You must provide an input for all fields. Please try again.");
        return;
      }

      if (!setHashSizeInModelBenchmarking(signView, signatureModelComparisonBenchmarking)
          && !isCustomCrossParameterBenchmarkingMode) {
        return;
      }
      if (!isCustomCrossParameterBenchmarkingMode) {
        signatureModelComparisonBenchmarking.createDefaultKeyConfigToHashFunctionsMap();
      }
      benchmarkingUtility = new BenchmarkingUtility();
      Task<Void> benchmarkingTask = createBenchmarkingTask(messageBatchFile,
          signatureModelComparisonBenchmarking);
      BenchmarkingUtility.beginBenchmarkWithUtility(benchmarkingUtility, "Signature Generation",
          benchmarkingTask,
          SignatureCreationControllerComparisonBenchmarking.this::handleBenchmarkingCompletion,
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
  void handleBenchmarkingCompletion() {
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


}
