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
 * the benchmarking functionalities in digital signature creation process. Key features include the
 * handling of message batch importation for signature generation, observer pattern implementations
 * for UI interactions, and dynamically loading different views based on the benchmarking mode.
 */
public abstract class AbstractSignatureCreationControllerBenchmarking extends
    AbstractSignatureBaseControllerBenchmarking {

  /**
   * The view component of the MVC pattern for the signing functionality. It handles the user
   * interface for the digital signature generation.
   */
  SignView signView;


  public AbstractSignatureCreationControllerBenchmarking(MainController mainController) {
    super(mainController);
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
  @Override
  public void showStandardView(Stage primaryStage) {
    mainController.showSignatureCreationStandard();
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
    mainController.showSignatureCreationBenchmarking();
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
