package uk.msci.project.rsa;

import javafx.concurrent.Task;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.stage.Stage;


/**
 * This class is part of the controller component specific to digital signature operations
 * responsible for handling user interactions for the signature creation process in benchmarking
 * mode. It also communicates with the Signature Model to perform the actual signature creation
 * logic.
 */
public class SignatureCreationControllerBenchmarking extends
    AbstractSignatureCreationControllerBenchmarking {


  /**
   * The model component of the MVC pattern that handles the data and business logic for digital
   * signature creation and verification.
   */
  SignatureModelBenchmarking signatureModelBenchmarking;


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
   * Displays the SignView interface. This method decides which version of the SignView to show
   * based on the current benchmarking and cross-parameter modes. If cross-parameter benchmarking is
   * enabled, it calls {@code showSignViewCrossBenchmarkingMode}. Otherwise, it loads the normal
   * benchmarking SignView. This method is responsible for setting up the SignView with the
   * necessary controllers and observers.
   *
   * @param primaryStage The primary stage of the application where the view will be displayed.
   */
  @Override
  public void showBenchmarkingView(Stage primaryStage) {
    isBenchmarkingMode = true;
    loadSignView("/SignView.fxml", () -> {
          this.signatureModelBenchmarking = new SignatureModelBenchmarking();
          setupObserversBenchmarkingMode(primaryStage, signView, signatureModelBenchmarking);
        },
        () ->
            preloadProvablySecureKeyBatch(signView, signatureModelBenchmarking));
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

      if ((signatureModelBenchmarking.getNumTrials() == 0)
          || signatureModelBenchmarking.getKeyBatchLength() == 0
          || signatureModelBenchmarking.getSignatureType() == null
          || signatureModelBenchmarking.getHashType() == null) {
        uk.msci.project.rsa.DisplayUtility.showErrorAlert(
            "You must provide an input for all fields. Please try again.");
        return;
      }

      if (!setHashSizeInModelBenchmarking(signView, signatureModelBenchmarking)) {
        return;
      }
      benchmarkingUtility = new BenchmarkingUtility();
      Task<Void> benchmarkingTask = createBenchmarkingTask(messageBatchFile,
          signatureModelBenchmarking);
      BenchmarkingUtility.beginBenchmarkWithUtility(benchmarkingUtility, "Signature Generation",
          benchmarkingTask,
          SignatureCreationControllerBenchmarking.this::handleBenchmarkingCompletion,
          mainController.getPrimaryStage());
    }
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


}
