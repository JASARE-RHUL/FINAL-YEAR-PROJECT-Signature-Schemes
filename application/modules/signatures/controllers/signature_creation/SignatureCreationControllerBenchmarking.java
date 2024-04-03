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

import uk.msci.project.rsa.MainController;
import uk.msci.project.rsa.BenchmarkingUtility;
import uk.msci.project.rsa.SignatureModelBenchmarking;
import uk.msci.project.rsa.AbstractSignatureBaseController;
import uk.msci.project.rsa.AbstractSignatureModelBenchmarking;
import uk.msci.project.rsa.SignatureBaseView;
import uk.msci.project.rsa.BenchmarkingContext;
import uk.msci.project.rsa.SignView;
import uk.msci.project.rsa.AbstractSignatureBaseControllerBenchmarking;
import uk.msci.project.rsa.ResultsControllerNormalBenchmarking;
import uk.msci.project.rsa.SignatureCreationContext;

/**
 * This class is part of the controller component specific to digital signature operations
 * responsible for handling user interactions for the signature creation process in benchmarking
 * mode. It also communicates with the Signature Model to perform the actual signature creation
 * logic.
 */
public class SignatureCreationControllerBenchmarking extends
    AbstractSignatureBaseControllerBenchmarking {

  /**
   * The view component of the MVC pattern for the signing functionality. It handles the user
   * interface for the digital signature generation.
   */
  SignView signView;


  /**
   * The model component of the MVC pattern that handles the data and business logic for digital
   * signature creation and verification.
   */
  SignatureModelBenchmarking signatureModel;


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
          this.signatureModel = new SignatureModelBenchmarking();
          setupObserversBenchmarkingMode(primaryStage, signView, signatureModel);
        },
        () ->
            preloadProvablySecureKeyBatch(signView, signatureModel));
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

      if ((signatureModel.getNumTrials() == 0)
          || signatureModel.getKeyBatchLength() == 0
          || signatureModel.getSignatureType() == null
          || signatureModel.getHashType() == null) {
        uk.msci.project.rsa.DisplayUtility.showErrorAlert(
            "You must provide an input for all fields. Please try again.");
        return;
      }

      if (!setHashSizeInModelBenchmarking(signView, signatureModel)) {
        return;
      }
      benchmarkingUtility = new BenchmarkingUtility();
      Task<Void> benchmarkingTask = createBenchmarkingTask(messageBatchFile,
          signatureModel);
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
  void handleBenchmarkingCompletion() {
    resetPreLoadedKeyParams();
    ResultsControllerNormalBenchmarking resultsController = new ResultsControllerNormalBenchmarking(
        mainController);
    BenchmarkingContext context = new SignatureCreationContext(signatureModel);
    resultsController.setContext(context);
    resultsController.showResultsView(null,
        signatureModel.getClockTimesPerTrial(),
        signatureModel.getKeyLengths(), false, 0);
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

        if (numMessages != Integer.parseInt(signatureView.getNumMessageField())) {
          uk.msci.project.rsa.DisplayUtility.showErrorAlert(
              "Message batch could not be imported. Please ensure the number "
                  + "of messages contained in the file matches the number of messages "
                  + "entered in the above field");

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
              new CancelImportTextBatchButtonObserver(signatureView, signatureModel));
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

    private SignatureBaseView signatureView;
    private AbstractSignatureModelBenchmarking signatureModelBenchmarking;

    public CancelImportTextBatchButtonObserver(SignatureBaseView signatureView,
        AbstractSignatureModelBenchmarking signatureModelBenchmarking) {
      this.signatureView = signatureView;
      this.signatureModelBenchmarking = signatureModelBenchmarking;
    }


    @Override
    public void handle(ActionEvent event) {
      signatureView.setTextFieldCheckmarkImageVisibility(false);
      signatureView.setMessageBatch("Please Import a message batch");
      signatureView.clearNumMessageField();
      signatureModelBenchmarking.setNumTrials(0);
      messageBatchFile = null;
      signatureView.setImportTextBatchBtnVisibility(true);
      signatureView.setCancelImportTextBatchButtonVisibility(false);
    }
  }


  /**
   * Displays the standard signature creation view. This method transitions the application to the
   * standard mode for signature creation, loading the corresponding view where the user can perform
   * typical signature generation operations without the complexities of benchmarking setups.
   *
   * @param primaryStage The primary stage of the application, serving as the main window for the
   *                     UI.
   */
  public void showStandardView(Stage primaryStage) {
    mainController.showSignatureCreationStandard();
  }


  /**
   * Displays the signature creation view in cross-parameter benchmarking mode. In this mode, users
   * can engage in a analysis of signature creation across different key sizes and configurations,
   * including standard and provably secure setups.
   *
   * @param primaryStage The primary stage of the application, serving as the main window for the
   *                     UI.
   */
  public void showCrossBenchmarkingView(Stage primaryStage) {
    mainController.showSignatureCreationComparisonBenchmarking();
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
  void loadSignView(String fxmlPath, Runnable observerSetup,
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
   * Creates a benchmarking task for signature generation. This task is responsible for processing a
   * batch of messages, generating signatures, and updating the UI with progress.
   *
   * @param messageFile The file containing the messages to be signed.
   * @return The task to be executed for benchmarking.
   */
  Task<Void> createBenchmarkingTask(File messageFile,
      AbstractSignatureModelBenchmarking signatureModelBenchmarking) {
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


}
