package uk.msci.project.rsa;

import javafx.concurrent.Task;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.stage.Stage;


/**
 * This class is part of the controller component specific to digital signature verification
 * operations responsible for handling user interactions for the signature verification process in
 * benchmarking mode. It also communicates with the Signature Model to perform the actual signature
 * verification logic.
 */
public class SignatureVerificationControllerBenchmarking extends
    AbstractSignatureVerificationControllerBenchmarking {

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
  public SignatureVerificationControllerBenchmarking(MainController mainController) {
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
  @Override
  public void showBenchmarkingView(Stage primaryStage) {
    isBenchmarkingMode = true;
    loadVerifyView("/VerifyView.fxml",
        () -> {
          this.signatureModelBenchmarking = new SignatureModelBenchmarking();
          setupObserversBenchmarkingMode(primaryStage, verifyView, signatureModelBenchmarking);
        },
        () -> preloadProvablySecureKeyBatch(verifyView, signatureModelBenchmarking));
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

      if ((signatureModelBenchmarking.getNumTrials() == 0)
          || signatureModelBenchmarking.getKeyBatchLength() == 0
          || signatureModel.getSignatureType() == null || numSignatures == 0
          || signatureModel.getHashType() == null) {
        uk.msci.project.rsa.DisplayUtility.showErrorAlert(
            "You must provide an input for all fields. Please try again.");
        return;
      }

      if (!setHashSizeInModelBenchmarking(verifyView, signatureModelBenchmarking)) {
        return;
      }
      // Show the progress dialog
      benchmarkingUtility = new BenchmarkingUtility();
      Task<Void> benchmarkingTask = createBenchmarkingTask(messageBatchFile, signatureBatchFile,
          signatureModelBenchmarking);
      BenchmarkingUtility.beginBenchmarkWithUtility(benchmarkingUtility, "Signature Verification",
          benchmarkingTask,
          SignatureVerificationControllerBenchmarking.this::handleBenchmarkingCompletion,
          mainController.getPrimaryStage());
    }
  }


  /**
   * Handles the completion of the benchmarking task for signature verification. This method is
   * called when the benchmarking task successfully completes. It initialises and sets up the
   * ResultsController with the appropriate context (SignatureVerificationContext) and displays the
   * results view with the gathered benchmarking data.
   */
  private void handleBenchmarkingCompletion() {
    resetPreLoadedKeyParams();
    ResultsControllerNormalBenchmarking resultsController = new ResultsControllerNormalBenchmarking(
        mainController);
    BenchmarkingContext context = new SignatureVerificationContext(signatureModelBenchmarking);
    resultsController.setContext(context);
    resultsController.showResultsView(null,
        signatureModelBenchmarking.getClockTimesPerTrial(),
        signatureModelBenchmarking.getKeyLengths(), false, 0);
  }


}
