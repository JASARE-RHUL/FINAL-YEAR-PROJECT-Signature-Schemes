package uk.msci.project.rsa;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.util.List;
import javafx.application.Platform;
import javafx.concurrent.Task;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.control.ButtonType;
import javafx.scene.control.Dialog;
import javafx.scene.control.Label;
import javafx.scene.control.ProgressBar;
import javafx.stage.Stage;


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
   * Displays the SignView interface. This method decides which version of the SignView to show
   * based on the current benchmarking and cross-parameter modes. If cross-parameter benchmarking is
   * enabled, it calls {@code showSignViewCrossBenchmarkingMode}. Otherwise, it loads the standard
   * SignView. This method is responsible for setting up the SignView with the necessary controllers
   * and observers.
   *
   * @param primaryStage The primary stage of the application where the view will be displayed.
   */
  public void showSignView(Stage primaryStage) {
    if (isKeyForComparisonMode && isCrossParameterBenchmarkingEnabled) {
      showSignViewCrossBenchmarkingMode(primaryStage);
      return;
    }
    try {
      FXMLLoader loader = new FXMLLoader(getClass().getResource("/SignView.fxml"));
      Parent root = loader.load();
      signView = loader.getController();
      this.signatureModel = new SignatureModel();

      // Set up observers for benchmarking mode SignView
      signView.addBenchmarkingModeToggleObserver(new ApplicationModeChangeObserver(
          () -> showSignViewStandardMode(primaryStage),
          () -> showSignView(primaryStage)
      ));
      signView.addCrossParameterToggleObserver(new CrossBenchmarkingModeChangeObserver(
          () -> showSignViewCrossBenchmarkingMode(primaryStage),
          () -> showSignView(primaryStage), new SignViewUpdateOperations(signView)));
      setupSignObserversBenchmarking(primaryStage);
      if (isKeyProvablySecure && this.importedKeyBatch != null
          && !isCrossParameterBenchmarkingEnabled) {
        updateWithImportedKey(new SignViewUpdateOperations(signView));
        signView.setImportKeyBatchButtonVisibility(false);
        signView.setCancelImportKeyButtonVisibility(true);
        signView.setProvableParamsHboxVisibility(true);
        signView.setProvablySecureParametersRadioSelected(true);
        signView.setCustomParametersRadioVisibility(false);
        signView.setStandardParametersRadioVisibility(false);
      }

      mainController.setScene(root);

    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  /**
   * Displays the SignView in standard mode. This method loads the SignView for the standard
   * (non-benchmarking) mode. It initialises the view, sets up the required observers for handling
   * events like text and key import, and displays the view on the provided stage.
   *
   * @param primaryStage The primary stage of the application where the view will be displayed.
   */
  public void showSignViewStandardMode(Stage primaryStage) {
    try {
      FXMLLoader loader = new FXMLLoader(getClass().getResource("/SignViewStandardMode.fxml"));
      Parent root = loader.load();
      signView = loader.getController();
      this.signatureModel = new SignatureModel();

      // Set up observers for benchmarking mode SignView
      signView.addBenchmarkingModeToggleObserver(new ApplicationModeChangeObserver(
          () -> showSignViewStandardMode(primaryStage),
          () -> showSignView(primaryStage)
      ));

      setupSignObservers(primaryStage);

      mainController.setScene(root);

    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  /**
   * Displays the SignView in cross-parameter benchmarking mode. This method loads the SignView
   * specifically configured for cross-parameter benchmarking. It initialises the view, sets up the
   * necessary observers for handling key and message batch imports, and displays the view on the
   * provided stage.
   *
   * @param primaryStage The primary stage of the application where the view will be displayed.
   */
  public void showSignViewCrossBenchmarkingMode(Stage primaryStage) {
    try {
      FXMLLoader loader = new FXMLLoader(
          getClass().getResource("/SignViewCrossBenchmarkingMode.fxml"));
      Parent root = loader.load();
      signView = loader.getController();
      this.signatureModel = new SignatureModel();
      updateWithImportedKey(new SignViewUpdateOperations(signView));
      if (isCrossParameterBenchmarkingEnabled && this.importedKeyBatch != null) {
        signView.setImportKeyBatchButtonVisibility(false);
        signView.setCancelImportKeyButtonVisibility(true);
      }
      signView.addBenchmarkingModeToggleObserver(new ApplicationModeChangeObserver(
          () -> showSignViewStandardMode(primaryStage),
          () -> showSignView(primaryStage)
      ));
      signView.addCrossParameterToggleObserver(new CrossBenchmarkingModeChangeObserver(
          () -> showSignViewCrossBenchmarkingMode(primaryStage),
          () -> showSignView(primaryStage), new SignViewUpdateOperations(signView)));
      setupSignObserversCrossBenchmarking(primaryStage);

      mainController.setScene(root);

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
    signView.addCancelImportSingleKeyButtonObserver(
        new CancelImportKeyButtonObserver(new SignViewUpdateOperations(signView)));
    signView.addSignatureSchemeChangeObserver(new SignatureSchemeChangeObserver());
    signView.addCreateSignatureObserver(
        new CreateSignatureObserver(new SignViewUpdateOperations(signView)));
    signView.addBackToMainMenuObserver(new BackToMainMenuObserver(signView));
    signView.addCloseNotificationObserver(new BackToMainMenuObserver(signView));
    signView.addCancelImportTextButtonObserver(
        new CancelImportTextButtonObserver(new SignViewUpdateOperations(signView)));

  }

  /**
   * Sets up benchmarking mode specific observers for the SignView controls.
   *
   * @param primaryStage The stage that observers will use for file dialogs.
   */
  private void setupSignObserversBenchmarking(Stage primaryStage) {
    signView.addImportTextBatchBtnObserver(
        new ImportObserver(primaryStage, new SignViewUpdateOperations(signView),
            this::handleMessageBatch, "*.txt"));
    signView.addImportKeyBatchButtonObserver(
        new ImportObserver(primaryStage, new SignViewUpdateOperations(signView),
            this::handleKeyBatch, "*.rsa"));
    signView.addCancelImportKeyButtonObserver(
        new CancelImportKeyBatchButtonObserver(new SignViewUpdateOperations(signView)));
    signView.addSignatureSchemeChangeObserver(new SignatureSchemeChangeObserver());
    signView.addParameterChoiceChangeObserver(
        new ParameterChoiceChangeObserver(new SignViewUpdateOperations(signView)));
    signView.addHashFunctionChangeObserver(
        new HashFunctionChangeObserver(new SignViewUpdateOperations(signView)));
    signView.addSigBenchmarkButtonObserver(
        new SignatureBenchmarkObserver(new SignViewUpdateOperations(signView)));
    signView.addBackToMainMenuObserver(new BackToMainMenuObserver(signView));
    signView.addProvableSchemeChangeObserver(
        new ProvableParamsChangeObserver(new SignViewUpdateOperations(signView)));
  }

  /**
   * Sets up observers for the SignView controls in cross-parameter benchmarking mode. This method
   * adds observers to handle events such as text batch import, key batch import, signature scheme
   * changes, benchmarking initiation, and navigation back to the main menu. The observers are
   * essential for capturing user interactions and updating the model and view accordingly in the
   * context of cross-parameter benchmarking.
   *
   * @param primaryStage The stage that observers will use for file dialogs.
   */
  private void setupSignObserversCrossBenchmarking(Stage primaryStage) {
    signView.addImportTextBatchBtnObserver(
        new ImportObserver(primaryStage, new SignViewUpdateOperations(signView),
            this::handleMessageBatch, "*.txt"));
    signView.addImportKeyBatchButtonObserver(
        new ImportObserver(primaryStage, new SignViewUpdateOperations(signView),
            this::handleKeyBatch, "*.rsa"));
    signView.addCancelImportKeyButtonObserver(
        new CancelImportKeyBatchButtonObserver(new SignViewUpdateOperations(signView)));
    signView.addSignatureSchemeChangeObserver(new SignatureSchemeChangeObserver());
    signView.addSigBenchmarkButtonObserver(
        new SignatureBenchmarkObserver(new SignViewUpdateOperations(signView)));
    signView.addStandardHashFunctionChangeObserver(new StandardHashFunctionChangeObserver());
    signView.addProvableHashFunctionChangeObserver(new ProvableHashFunctionChangeObserver());
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

    private ViewUpdate viewOps;

    public CreateSignatureObserver(ViewUpdate viewOps) {
      this.viewOps = viewOps;
    }

    @Override
    public void handle(ActionEvent event) {
      hashOutputSize = signView.getHashOutputSize();
      if ((signView.getTextInput().equals("") && message == null)
          || signatureModel.getKey() == null
          || signatureModel.getSignatureType() == null
          || signatureModel.getHashType() == null) {
        uk.msci.project.rsa.DisplayUtility.showErrorAlert(
            "You must provide an input for all fields. Please try again.");
        return;
      }

      if (!setHashSizeInModel(new SignViewUpdateOperations(signView))) {
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
   * Observer for initiating the signature generation benchmark. This class handles the event
   * triggered for starting the benchmarking process. Depending on the benchmarking mode, it either
   * initiates a standard benchmarking task or calls 'handleBenchmarkingInitiationComparisonMode'
   * for comparison mode benchmarking. It ensures the necessary preconditions are met, sets up the
   * task, and manages the progress display on the UI.
   */
  class SignatureBenchmarkObserver implements EventHandler<ActionEvent> {

    private ViewUpdate viewOps;

    public SignatureBenchmarkObserver(ViewUpdate viewOps) {
      this.viewOps = viewOps;
    }

    @Override
    public void handle(ActionEvent event) {
      hashOutputSize = signView.getHashOutputSize();

      if (isCrossParameterBenchmarkingEnabled) {
        handleBenchmarkingInitiationComparisonMode();
        return;
      }

      if ((signatureModel.getNumTrials() == 0)
          || signatureModel.getPrivateKeyBatchLength() == 0
          || signatureModel.getSignatureType() == null
          || signatureModel.getHashType() == null) {
        uk.msci.project.rsa.DisplayUtility.showErrorAlert(
            "You must provide an input for all fields. Please try again.");
        return;
      }

      if (!setHashSizeInModel(new SignViewUpdateOperations(signView))) {
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
   * Handles the initiation of the benchmarking process in comparison mode. This method checks for
   * required inputs specific to comparison mode benchmarking and initiates the benchmarking task.
   * It sets up the progress dialog and begins the task for generating signatures across different
   * key sizes and parameter settings, providing feedback on the progress to the user.
   */
  private void handleBenchmarkingInitiationComparisonMode() {

    if ((signatureModel.getNumTrials() == 0)
        || signatureModel.getPrivateKeyBatchLength() == 0
        || signatureModel.getSignatureType() == null
        || signatureModel.getCurrentFixedHashType_ComparisonMode() == null
        || signatureModel.getCurrentProvableHashType_ComparisonMode() == null) {
      uk.msci.project.rsa.DisplayUtility.showErrorAlert(
          "You must provide an input for all fields. Please try again.");
      return;
    }

    if (!setHashSizeInModel(new SignViewUpdateOperations(signView))) {
      return;
    }
    // Show the progress dialog
    Dialog<Void> progressDialog = uk.msci.project.rsa.DisplayUtility.showProgressDialog(
        mainController.getPrimaryStage(), "Signature Generation");
    ProgressBar progressBar = (ProgressBar) progressDialog.getDialogPane()
        .lookup("#progressBar");
    Label progressLabel = (Label) progressDialog.getDialogPane().lookup("#progressLabel");

    Task<Void> benchmarkingTask = createBenchmarkingTaskComparisonMode(messageBatchFile,
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
      handleBenchmarkingCompletionComparisonMode(); // Handle completion
    });

    benchmarkingTask.setOnFailed(e -> {
      progressDialog.close();
      uk.msci.project.rsa.DisplayUtility.showErrorAlert(
          "Error: Benchmarking failed. Please try again.");

    });
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
   * Creates a benchmarking task for signature generation in comparison mode. This task is
   * responsible for processing a batch of messages, generating signatures, and updating the UI with
   * progress.
   *
   * @param messageFile   The file containing the messages to be signed.
   * @param progressBar   UI component to display progress.
   * @param progressLabel UI component to display progress text.
   * @return The task to be executed for benchmarking.
   */
  private Task<Void> createBenchmarkingTaskComparisonMode(File messageFile, ProgressBar progressBar,
      Label progressLabel) {
    return new Task<>() {
      @Override
      protected Void call() throws Exception {
        signatureModel.batchGenerateSignatures_ComparisonMode(messageFile,
            progress -> Platform.runLater(() -> {
              progressBar.setProgress(progress);
              progressLabel.setText(String.format("%.0f%%", progress * 100));
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
    ResultsController resultsController = new ResultsController(mainController);
    BenchmarkingContext context = new SignatureCreationContext(signatureModel);
    resultsController.setContext(context);
    resultsController.showResultsView(mainController.getPrimaryStage(),
        signatureModel.getClockTimesPerTrial(), signatureModel.getPrivKeyLengths());
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
    BenchmarkingContext context = new SignatureCreationContext(signatureModel);
    resultsController.setContext(context);

    resultsController.showResultsView(mainController.getPrimaryStage(),
        signatureModel.getClockTimesPerTrial(), signatureModel.getPrivKeyLengths(), true,
        signatureModel.getNumKeySizesForComparisonMode());
  }


  /**
   * Processes a file containing a batch of messages for signature creation. Validates the file's
   * content and updates the model and UI accordingly. Ensures the file format is correct (Ensures
   * the file format is correct i.e., no empty lines apart from the end of the file) and contains
   * the expected number of messages.
   *
   * @param file    The file containing messages to be signed.
   * @param viewOps Operations to update the view based on file processing.
   */
  public void handleMessageBatch(File file, ViewUpdate viewOps) {
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
          viewOps.setMessageBatchName(file.getName());
          viewOps.setTextFileCheckmarkImage();
          viewOps.setTextFileCheckmarkVisibility(true);
          viewOps.setBatchMessageVisibility(true);
          signView.setNumMessageFieldEditable(false);
          viewOps.setImportTextBatchBtnVisibility(false);
          viewOps.setCancelImportTextBatchButtonVisibility(true);
          signView.addCancelImportTextBatchButtonObserver(
              new CancelImportTextBatchButtonObserver(new SignViewUpdateOperations(signView)));
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
   * Handles the file selected by the user for a batch of keys. It validates the keys and updates
   * the model and view accordingly. It expects the key file to contain a line separated text of
   * comma delimited positive integers (with length 2 i.e., modulus and exponent) and updates the
   * view based on the result of the key validation.
   *
   * @param file    The file selected by the user containing a batch of keys.
   * @param viewOps The {@code ViewUpdate} operations that will update the view.
   */
  public boolean handleKeyBatch(File file, ViewUpdate viewOps) {
    if (super.handleKeyBatch(file, viewOps)) {
      signView.setImportKeyBatchButtonVisibility(false);
      signView.setCancelImportKeyButtonVisibility(true);
    }
    return true;
  }

  /**
   * Handles the file selected by the user for a single key (non-benchmarking mode). It validates
   * the keys and updates the model and view accordingly. It expects the key file to contain a
   * single line with comma delimited positive integers (with length 2 i.e., modulus and exponent)
   * and updates the view based on the result of the key validation.
   *
   * @param file    The file selected by the user containing a batch of keys.
   * @param viewOps The {@code ViewUpdate} operations that will update the view.
   */
  public boolean handleKey(File file, ViewUpdate viewOps) {
    if (super.handleKeyBatch(file, viewOps)) {
      signView.setImportKeyButtonVisibility(false);
      signView.setCancelImportSingleKeyButtonVisibility(true);
    }
    return true;
  }


  /**
   * Observer for canceling the import of a text batch. Handles the event when the user decides to
   * cancel the import of a batch of messages by replacing the cancel button with the original
   * import button and resetting corresponding text field that display the name of the file.
   */
  class CancelImportTextBatchButtonObserver implements EventHandler<ActionEvent> {

    private ViewUpdate viewOps;

    public CancelImportTextBatchButtonObserver(ViewUpdate viewOps) {
      this.viewOps = viewOps;
    }

    @Override
    public void handle(ActionEvent event) {
      viewOps.setTextFileCheckmarkVisibility(false);
      viewOps.setMessageBatchName("Please Import a message batch");
      signView.clearNumMessageField();
      signatureModel.setNumTrials(0);
      messageBatchFile = null;
      viewOps.setImportTextBatchBtnVisibility(true);
      viewOps.setCancelImportTextButtonVisibility(false);
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
