package uk.msci.project.rsa;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.util.List;
import javafx.application.Platform;
import javafx.concurrent.Task;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.ButtonType;
import javafx.scene.control.Dialog;
import javafx.scene.control.Label;
import javafx.scene.control.ProgressBar;
import javafx.stage.Stage;
import javafx.util.Pair;


/**
 * This class is part of the controller component specific to digital signature operations
 * responsible for handling user interactions for the signature creation process. It also
 * communicates with the Signature Model to perform the actual signature creation logic.
 */
public class SignatureCreationController extends SignatureBaseController {

  /**
   * The view component of the MVC pattern for the signing functionality. It handles the user
   * interface for the digital signature generation.
   */
  private SignView signView;

  /**
   * The message to be signed, stored as a byte array.
   */
  private byte[] message;


  /**
   * The digital signature generated after signing the message. It is stored as a String for storage
   * purposes.
   */
  private String signature;

  /**
   * Constructs a SignatureCreationController with a reference to the MainController to be used in
   * the event of the user initiating a switch back to main menu.
   *
   * @param mainController The main controller that this controller is part of.
   */
  public SignatureCreationController(MainController mainController) {
    super(mainController);
  }

  /**
   * Initialises and displays the SignView stage. It loads the FXML for the SignView and sets up the
   * scene and the stage.
   *
   * @param primaryStage The primary stage for this application.
   */
  public void showSignView(Stage primaryStage) {
    try {
      FXMLLoader loader = new FXMLLoader(getClass().getResource("/SignView.fxml"));
      Parent root = loader.load();
      signView = loader.getController();
      this.signatureModel = new SignatureModel();

      // Set up observers for benchmarking mode SignView
      setupSignObserversBenchmarking(primaryStage);

      Scene scene = new Scene(root);
      scene.getStylesheets().add("/SignatureView.css");
      primaryStage.setScene(scene);

    } catch (IOException e) {
      e.printStackTrace();
    }
  }


  /**
   * Sets up observers for the SignView controls. Observers are added to handle events like text
   * import, key import, and signature scheme changes.
   *
   * @param primaryStage The stage that observers will use for file dialogs.
   */
  private void setupSignObservers(Stage primaryStage) {
    signView.addImportTextObserver(
        new ImportObserver(primaryStage, new SignViewUpdateOperations(signView),
            this::handleMessageFile, "*.txt"));
    signView.addImportKeyObserver(
        new ImportObserver(primaryStage, new SignViewUpdateOperations(signView),
            this::handleKey, "*.rsa"));
    signView.addSignatureSchemeChangeObserver(new SignatureSchemeChangeObserver());
    signView.addCreateSignatureObserver(new CreateSignatureObserver());
    signView.addBackToMainMenuObserver(new BackToMainMenuObserver(signView));
    signView.addCloseNotificationObserver(new BackToMainMenuObserver(signView));
  }

  private void setupSignObserversBenchmarking(Stage primaryStage) {
    signView.addImportTextBatchBtnObserver(
        new ImportObserver(primaryStage, new SignViewUpdateOperations(signView),
            this::handleMessageBatch, "*.txt"));
    signView.addImportKeyBatchButtonObserver(
        new ImportObserver(primaryStage, new SignViewUpdateOperations(signView),
            this::handleKeyBatch, "*.rsa"));
    signView.addCancelImportKeyButtonObserver(
        new CancelImportKeyButtonObserver(new SignViewUpdateOperations(signView)));
    signView.addSignatureSchemeChangeObserver(new SignatureSchemeChangeObserver());
    signView.addParameterChoiceChangeObserver(new ParameterChoiceChangeObserver());
    signView.addSigBenchmarkButtonObserver(new SignatureBenchmarkObserver());
    signView.addBackToMainMenuObserver(new BackToMainMenuObserver(signView));
  }

  /**
   * Initialises and sets up the post-generation observers for the SignView. This includes observers
   * for copying the signature to the clipboard and exporting the signature. This method is called
   * after a signature has been generated.
   */
  public void setupPostGenerationObservers() {
    signView.addCopySignatureObserver(new CopyToClipboardObserver("signature", signature,
        "Failed to copy signature to clipboard."));
    signView.addExportSignatureObserver(
        new ExportObserver("signature.rsa", signature, "Signature was successfully exported!"));

  }


  /**
   * The observer for creating signatures. This class handles the action event triggered for the
   * signature generation process. It checks for necessary inputs, generates the signature using the
   * selected scheme, and updates the view with post-generation options.
   */
  class CreateSignatureObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
      if ((signView.getTextInput().equals("") && message == null)
          || signatureModel.getKey() == null
          || signView.getSelectedSignatureScheme() == null) {
        uk.msci.project.rsa.DisplayUtility.showErrorAlert(
            "You must provide an input for all fields. Please try again.");
        return;
      }
      try {
        String textToSign = signView.getTextInput();
        if (!textToSign.equals("")) {
          message = textToSign.getBytes();
        }
        signatureModel.instantiateSignatureScheme();

        signature = new BigInteger(1, signatureModel.sign(message)).toString();
        setupPostGenerationObservers();
        if (signatureModel.getNonRecoverableM().length == 0) {
          signView.addExportNonRecoverableMessageObserver(
              new ExportObserver("nonRecoverableMessage.txt",
                  new String(signatureModel.getNonRecoverableM()),
                  "Non recoverable message was successfully exported!"));
          signView.addCopyNonRecoverableMessageObserver(
              new CopyToClipboardObserver("Non-recoverable message",
                  new String(signatureModel.getNonRecoverableM()),
                  "Failed to copy non-recoverable message to clipboard."));
          signView.setRecoveryOptionsVisibility(true);
        }
        signView.showNotificationPane();
      } catch (Exception e) {
        uk.msci.project.rsa.DisplayUtility.showErrorAlert(
            "There was an error generating a signature. Please try again.");
        e.printStackTrace();

      }
    }
  }

  /**
   * Observer for initiating the signature generation benchmark. Handles the event triggered for
   * starting the benchmarking process, sets up the task, and shows the progress on the UI.
   */
  class SignatureBenchmarkObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
      if ((signatureModel.getNumTrials() == 0)
          || signatureModel.getPrivateKeyBatchLength() == 0
          || signView.getSelectedSignatureScheme() == null) {
        uk.msci.project.rsa.DisplayUtility.showErrorAlert(
            "You must provide an input for all fields. Please try again.");
        return;
      }

      // Show the progress dialog
      Dialog<Void> progressDialog = uk.msci.project.rsa.DisplayUtility.showProgressDialog(
          mainController.getPrimaryStage(), "Signature Generation");
      ProgressBar progressBar = (ProgressBar) progressDialog.getDialogPane()
          .lookup("#progressBar");
      Label progressLabel = (Label) progressDialog.getDialogPane().lookup("#progressLabel");
      
      Task<Void> benchmarkingTask = createBenchmarkingTask(messageBatchFile,
          progressBar, progressLabel);
      new Thread(benchmarkingTask).start();

      progressDialog.getDialogPane().lookupButton(ButtonType.CANCEL)
          .addEventFilter(ActionEvent.ACTION, e -> {
            if (benchmarkingTask.isRunning()) {
              benchmarkingTask.cancel();
            }
          });

      benchmarkingTask.setOnSucceeded(e -> {
        progressDialog.close();
        handleBenchmarkingCompletion(); // Handle completion
      });

      benchmarkingTask.setOnFailed(e -> {
        progressDialog.close();
        uk.msci.project.rsa.DisplayUtility.showErrorAlert(
            "Error: Benchmarking failed. Please try again.");

      });

    }

  }

  /**
   * Creates a benchmarking task for signature generation. This task is responsible for processing a
   * batch of messages, generating signatures, and updating the UI with progress.
   *
   * @param messageFile   The file containing the messages to be signed.
   * @param progressBar   UI component to display progress.
   * @param progressLabel UI component to display progress text.
   * @return The task to be executed for benchmarking.
   */

  private Task<Void> createBenchmarkingTask(File messageFile, ProgressBar progressBar,
      Label progressLabel) {
    return new Task<>() {
      @Override
      protected Void call() throws Exception {
        signatureModel.batchCreateSignatures(messageFile, progress -> Platform.runLater(() -> {
          progressBar.setProgress(progress);
          progressLabel.setText(String.format("%.0f%%", progress * 100));
        }));
        return null;
      }
    };

  }

  /**
   * Handles the completion of the benchmarking task for signature creation. This method is called when
   * the benchmarking task successfully completes. It initialises and sets up the ResultsController
   * with the appropriate context (SignatureCreationContext) and displays the results view with the
   * gathered benchmarking data.
   */
  private void handleBenchmarkingCompletion() {
    ResultsController resultsController = new ResultsController(mainController);
    BenchmarkingContext context = new SignatureCreationContext(signatureModel);
    resultsController.setContext(context);
    resultsController.showResultsView(mainController.getPrimaryStage(),
        signatureModel.getClockTimesPerTrial());
  }


  /**
   * Processes a file containing a batch of messages for signature creation. Validates the file's
   * content and updates the model and UI accordingly. Ensures the file format is correct and
   * contains the expected number of messages.
   *
   * @param file    The file containing messages to be signed.
   * @param viewOps Operations to update the view based on file processing.
   */
  public void handleMessageBatch(File file, ViewUpdate viewOps) {
    int numMessages = 0;
    boolean encounteredNonEmptyLine = false;

    try (BufferedReader messageReader = new BufferedReader(new FileReader(file))) {
      String messageString;
      while ((messageString = messageReader.readLine()) != null) {
        if (!messageString.isEmpty()) {
          encounteredNonEmptyLine = true;
          numMessages++;
        } else if (encounteredNonEmptyLine) {
          uk.msci.project.rsa.DisplayUtility.showErrorAlert(
              "Invalid message batch. Please make sure the file contains no empty lines.");
        }
      }
      this.messageBatchFile = file;
      if (numMessages != Integer.parseInt(signView.getNumMessageField())) {
        uk.msci.project.rsa.DisplayUtility.showErrorAlert(
            "Message batch could not be imported. Please ensure the number "
                + "of messages contained in the file matches the number of messages "
                + "entered in the above field");
        return;
      } else {
        signatureModel.setNumTrials(numMessages);
        viewOps.setMessageBatchName(file.getName());
        viewOps.setTextFileCheckmarkImage();
        viewOps.setTextFileCheckmarkVisibility(true);
        viewOps.setBatchMessageVisibility(true);
        signView.setNumMessageFieldEditable(false);
        signView.setImportTextBatchBtnVisibility(false);
        signView.setCancelImportTextButtonVisibility(true);
        signView.addCancelImportTextButtonObserver(
            new CancelImportTextButtonObserver(new SignViewUpdateOperations(signView)));
      }

    } catch (Exception e) {
      uk.msci.project.rsa.DisplayUtility.showErrorAlert(
          "Invalid message batch. Please make sure the file contains a contiguous sequence of new line separated messages that matches the number entered in the the above field.");

    }


  }

  /**
   * Observer for canceling the import of a text batch. Handles the event triggered when the user
   * decides to cancel the import of a batch of messages.
   */
  class CancelImportTextButtonObserver implements EventHandler<ActionEvent> {

    private ViewUpdate viewOps;

    public CancelImportTextButtonObserver(ViewUpdate viewOps) {
      this.viewOps = viewOps;
    }

    @Override
    public void handle(ActionEvent event) {
      viewOps.setTextFileCheckmarkVisibility(false);
      viewOps.setMessageBatchName("Please Import a message batch");
      signView.clearNumMessageField();
      signatureModel.setNumTrials(0);
      messageBatchFile = null;
      signView.setImportTextBatchBtnVisibility(true);
      signView.setCancelImportTextButtonVisibility(false);
    }
  }

  /**
   * Observer for canceling the import of a key batch. Handles the event when the user decides to
   * cancel the import of a batch of keys.
   */
  class CancelImportKeyButtonObserver implements EventHandler<ActionEvent> {

    private ViewUpdate viewOps;

    public CancelImportKeyButtonObserver(ViewUpdate viewOps) {
      this.viewOps = viewOps;
    }

    @Override
    public void handle(ActionEvent event) {
      viewOps.setCheckmarkVisibility(false);
      ;
      viewOps.setKeyName("Please Import a private key batch");
      signatureModel.clearPrivateKeyBatch();
      signatureModel.clearPublicKeyBatch();
      signView.setCancelImportKeyButtonVisibility(false);
      signView.setImportKeyBatchButtonVisibility(true);

    }
  }


  /**
   * Sets the message to be signed. This method is used to update the message that will be signed by
   * the signature model.
   *
   * @param message The message to be signed, represented as a byte array.
   */
  @Override
  public void setMessage(byte[] message) {
    this.message = message;
  }

}
