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
 * This abstract class extends AbstractSignatureBaseControllerBenchmarking to specifically manage
 * the benchmarking functionalities in digital signature verification process.  Key features include
 * the handling of message batch importation for signature verification, observer pattern
 * implementations for UI interactions, and dynamically loading different views based on the
 * benchmarking mode.
 */
public abstract class AbstractSignatureVerificationControllerBenchmarking extends
    AbstractSignatureBaseControllerBenchmarking {

  /**
   * The view component of the MVC pattern for the verification functionality. It handles the user
   * interface for the digital signature verification.
   */
  VerifyView verifyView;


  /**
   * The number of signatures involved in the batch verification process. This field holds the total
   * count of signatures that will be verified during the benchmarking task.
   */
  int numSignatures;

  int numTrials;

  public AbstractSignatureVerificationControllerBenchmarking(MainController mainController) {
    super(mainController);
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
    numTrials = checkFileForNonEmptyLines(file, "message");
    if (numTrials > 0) {
      messageBatchFile = file;
      signatureModelBenchmarking.setNumTrials(numTrials);
      signatureView.setMessageBatch(file.getName());
      signatureView.setTextFileCheckmarkImage();
      signatureView.setTextFieldCheckmarkImageVisibility(true);
      signatureView.setMessageBatchFieldVisibility(true);
      signatureView.setImportTextBatchBtnVisibility(false);
      signatureView.setCancelImportTextBatchButtonVisibility(true);
      signatureView.addCancelImportTextBatchButtonObserver(
          new CancelImportTextBatchButtonObserver(signatureView));
    }
  }


  /**
   * Observer for canceling the import of a text batch. Handles the event when the user decides to
   * cancel the import of a batch of messages by replacing the cancel button with the original
   * import button and resetting corresponding text field that display the name of the file.
   */
  class CancelImportTextBatchButtonObserver implements EventHandler<ActionEvent> {

    private SignatureBaseView signatureView;

    public CancelImportTextBatchButtonObserver(SignatureBaseView signatureView) {
      this.signatureView = signatureView;
    }

    @Override
    public void handle(ActionEvent event) {
      signatureView.setTextFieldCheckmarkImageVisibility(false);
      signatureView.setMessageBatch("Please Import a message batch");
      messageBatchFile = null;
      signatureView.setCancelImportTextBatchButtonVisibility(false);
      signatureView.setImportTextBatchBtnVisibility(true);

    }
  }


  /**
   * Processes a file containing a batch of signatures for signature verification. Validates the
   * file's content and updates the model and UI accordingly. Ensures the file format is correct and
   * contains a valid batch of signatures. This method is essential for handling batch operations in
   * signature verification benchmarking scenarios.
   *
   * @param file                       The file containing a batch of signatures for verification.
   * @param signatureView              The signature view to be updated with the imported signature
   *                                   batch.
   * @param signatureModelBenchmarking The benchmarking model used for processing the signature
   *                                   batch.
   */
  public void handleSignatureBatch(File file, SignatureBaseView signatureView,
      AbstractSignatureModelBenchmarking signatureModelBenchmarking) {
    numSignatures = checkFileForNonEmptyLines(file, "signature");
    if (signatureView instanceof VerifyView verifyView && numSignatures > 0) {
      signatureBatchFile = file;
      verifyView.setSignatureBatch(file.getName());
      verifyView.setSigFileCheckmarkImage();
      verifyView.setSigFileCheckmarkImageVisibility(true);
      verifyView.setSignatureBatchFieldVisibility(true);
      verifyView.setImportSigBatchBtnVisibility(false);
      verifyView.setCancelImportSigBatchButtonVisibility(true);
      verifyView.addCancelImportSigBatchButtonObserver(
          new CancelImportSigButtonObserver(verifyView));

    } else {
      uk.msci.project.rsa.DisplayUtility.showErrorAlert(
          "Invalid signature batch. Please make sure the file is not empty.");
    }
  }

  /**
   * Observer for canceling the import of a signature batch. Handles the event when the user decides
   * to cancel the import of a batch of signatures.
   */
  class CancelImportSigButtonObserver implements EventHandler<ActionEvent> {

    private VerifyView verifyView;

    public CancelImportSigButtonObserver(VerifyView verifyView) {
      this.verifyView = verifyView;
    }

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
   * Displays the standard signature creation view. This method transitions the application to the
   * standard mode for signature creation, loading the corresponding view where the user can perform
   * typical signature generation operations without the complexities of benchmarking setups.
   *
   * @param primaryStage The primary stage of the application, serving as the main window for the
   *                     UI.
   */
  @Override
  public void showStandardView(Stage primaryStage) {
    mainController.showSignatureVerificationStandard();
  }


  /**
   * Displays the signature creation view in benchmarking mode. It facilitates the comparison of
   * signature creation performance across different parameters types.
   *
   * @param primaryStage The primary stage of the application, serving as the main window for the
   *                     UI.
   */
  @Override
  public void showBenchmarkingView(Stage primaryStage) {
    mainController.showSignatureVerificationBenchmarking();
  }

  /**
   * Displays the signature creation view in cross-parameter benchmarking mode. In this mode, users
   * can engage in a analysis of signature creation across different key sizes and configurations,
   * including standard and provably secure setups.
   *
   * @param primaryStage The primary stage of the application, serving as the main window for the
   *                     UI.
   */
  @Override
  public void showCrossBenchmarkingView(Stage primaryStage) {
    mainController.showSignatureVerificationComparisonBenchmarking();
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
  void loadVerifyView(String fxmlPath, Runnable observerSetup,
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
   * Creates a task for benchmarking the signature verification process. This task verifies a batch
   * of signatures against a batch of messages and updates the progress on the UI. It is used in
   * standard benchmarking mode.
   *
   * @param messageFile        The file containing a batch of messages to be verified.
   * @param batchSignatureFile The file containing a batch of signatures corresponding to the
   *                           messages.
   * @return A Task<Void> that will execute the benchmarking process in the background.
   */
  Task<Void> createBenchmarkingTask(File messageFile, File batchSignatureFile,
      AbstractSignatureModelBenchmarking signatureModelBenchmarking) {
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


}
