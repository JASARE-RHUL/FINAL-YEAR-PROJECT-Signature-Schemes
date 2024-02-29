package uk.msci.project.rsa;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
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
  public SignatureCreationController(MainController mainController) {
    super(mainController);
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
      this.signatureModel = new SignatureModel();

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
  public void showSignView(Stage primaryStage) {
    if (isKeyForComparisonMode && isCrossParameterBenchmarkingEnabled) {
      showSignViewCrossBenchmarkingMode(primaryStage);
      return;
    }
    loadSignView("/SignView.fxml", () -> setupSignObserversBenchmarking(primaryStage), () -> {
      if (isSingleKeyProvablySecure && this.importedKeyBatch != null
          && !isCrossParameterBenchmarkingEnabled) {
        updateWithImportedKeyBatch(signView);
        signView.setImportKeyBatchButtonVisibility(false);
        signView.setCancelImportKeyButtonVisibility(true);
        signView.setProvableParamsHboxVisibility(true);
        signView.setProvablySecureParametersRadioSelected(true);
        signView.setCustomParametersRadioVisibility(false);
        signView.setStandardParametersRadioVisibility(false);
      }
    });

  }

  /**
   * Displays the SignView in standard mode. This method loads the SignView for the standard
   * (non-benchmarking) mode. It initialises the view, sets up the required observers for handling
   * events like text and key import, and displays the view on the provided stage.
   *
   * @param primaryStage The primary stage of the application where the view will be displayed.
   */
  public void showSignViewStandardMode(Stage primaryStage) {
    loadSignView("/SignViewStandardMode.fxml", () -> setupSignObserversStandard(primaryStage),
        () -> {
          if (isSingleKeyProvablySecure && this.importedKeyBatch != null) {
            updateWithImportedKey(signView);
            signView.setImportKeyButtonVisibility(false);
            signView.setCancelImportSingleKeyButtonVisibility(true);
            signView.setProvableParamsHboxVisibility(true);
            signView.setProvablySecureParametersRadioSelected(true);
            signView.setCustomParametersRadioVisibility(false);
            signView.setStandardParametersRadioVisibility(false);
          }
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
  public void showSignViewCrossBenchmarkingMode(Stage primaryStage) {
    loadSignView("/SignViewCrossBenchmarkingMode.fxml",
        () -> setupSignObserversCrossBenchmarking(primaryStage), () -> {
          updateWithImportedKeyBatch(signView);
          signatureModel.setNumKeysPerKeySizeComparisonMode(keyConfigurationStrings.size());
          signatureModel.setKeyConfigurationStrings(keyConfigurationStrings);
          if (isCrossParameterBenchmarkingEnabled && this.importedKeyBatch != null) {
            signView.setImportKeyBatchButtonVisibility(false);
            signView.setCancelImportKeyButtonVisibility(true);
          }
        });

  }

  /**
   * Sets up observers specific to non-cross-benchmarking mode. This includes observers for handling
   * signature scheme changes, parameter choice changes, hash function changes, and provable scheme
   * changes.
   */
  private void setupNonCrossBenchmarkingObservers() {
    signView.addParameterChoiceChangeObserver(
        new ParameterChoiceChangeObserver(signView));
    signView.addHashFunctionChangeObserver(
        new HashFunctionChangeObserver(signView));
    signView.addProvableSchemeChangeObserver(
        new ProvableParamsChangeObserver(signView));
  }

  /**
   * Sets up observers common to all modes of the SignView. This includes observers for benchmarking
   * mode toggle, back to main menu actions, and other common functionalities.
   *
   * @param primaryStage The primary stage of the application where the view will be displayed.
   */
  private void setupCommonToAllObservers(Stage primaryStage) {
    signView.addSignatureSchemeChangeObserver(new SignatureSchemeChangeObserver());
    signView.addBenchmarkingModeToggleObserver(new ApplicationModeChangeObserver(
        () -> showSignViewStandardMode(primaryStage),
        () -> showSignView(primaryStage)
    ));
    signView.addBackToMainMenuObserver(new BackToMainMenuObserver(signView));
  }

  /**
   * Sets up observers specific to benchmarking mode. This includes observers for importing text
   * batches, key batches, canceling key batch import, and starting the benchmarking process.
   *
   * @param primaryStage The primary stage of the application where the view will be displayed.
   */
  private void setupBenchmarkingObservers(Stage primaryStage) {
    signView.addImportTextBatchBtnObserver(
        new ImportObserver(primaryStage, signView, this::handleMessageBatch, "*.txt"));
    signView.addImportKeyBatchButtonObserver(
        new ImportObserver(primaryStage, signView,
            this::handleKeyBatch, "*.rsa"));
    signView.addCancelImportKeyButtonObserver(
        new CancelImportKeyBatchButtonObserver(signView));
    signView.addSigBenchmarkButtonObserver(
        new SignatureBenchmarkObserver());
    signView.addCrossParameterToggleObserver(new CrossBenchmarkingModeChangeObserver(
        () -> showSignViewCrossBenchmarkingMode(primaryStage),
        () -> showSignView(primaryStage), signView));
  }


  /**
   * Sets up observers for the SignView in the standard (non-benchmarking) mode. This method
   * initialises observers for importing text, keys, canceling imports, creating signatures, and
   * other standard mode functionalities.
   *
   * @param primaryStage The primary stage of the application where the view will be displayed.
   */
  private void setupSignObserversStandard(Stage primaryStage) {
    signView.addImportTextObserver(
        new ImportObserver(primaryStage, signView,
            this::handleMessageFile, "*.txt"));
    signView.addImportKeyObserver(
        new ImportObserver(primaryStage, signView,
            this::handleKey, "*.rsa"));
    signView.addCancelImportSingleKeyButtonObserver(
        new CancelImportKeyButtonObserver(signView));
    signView.addCreateSignatureObserver(
        new CreateSignatureObserver());
    signView.addCloseNotificationObserver(new BackToMainMenuObserver(signView));
    signView.addCancelImportTextButtonObserver(
        new CancelImportTextButtonObserver(signView));
    setupNonCrossBenchmarkingObservers();
    setupCommonToAllObservers(primaryStage);

  }


  /**
   * Sets up observers for the SignView in benchmarking mode. This method initialises observers
   * specific to benchmarking, including text batch imports, key batch imports, benchmarking
   * initiation, and additional benchmarking-specific functionalities.
   *
   * @param primaryStage The primary stage of the application where the view will be displayed.
   */
  private void setupSignObserversBenchmarking(Stage primaryStage) {
    setupCommonToAllObservers(primaryStage);
    setupBenchmarkingObservers(primaryStage);
    setupNonCrossBenchmarkingObservers();
  }

  /**
   * Sets up observers for the SignView in cross-parameter benchmarking mode. This method
   * initialises observers specific to cross-parameter benchmarking, including standard and provable
   * hash function changes, and other functionalities specific to this mode.
   *
   * @param primaryStage The primary stage of the application where the view will be displayed.
   */
  private void setupSignObserversCrossBenchmarking(Stage primaryStage) {
    setupCommonToAllObservers(primaryStage);
    setupBenchmarkingObservers(primaryStage);
    signView.addStandardHashFunctionChangeObserver(new StandardHashFunctionChangeObserver());
    signView.addProvableHashFunctionChangeObserver(new ProvableHashFunctionChangeObserver());
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
      hashOutputSize = signView.getHashOutputSize();
      if ((signView.getTextInput().equals("") && message == null)
          || signatureModel.getKey() == null
          || signatureModel.getSignatureType() == null
          || signatureModel.getHashType() == null) {
        uk.msci.project.rsa.DisplayUtility.showErrorAlert(
            "You must provide an input for all fields. Please try again.");
        return;
      }

      if (!setHashSizeInModel(signView)) {
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
        resetPreLoadedKeyParams();
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

      if (!setHashSizeInModel(signView)) {
        return;
      }
      benchmarkingUtility = new BenchmarkingUtility();
      Task<Void> benchmarkingTask = createBenchmarkingTask(messageBatchFile);
      BenchmarkingUtility.beginBenchmarkWithUtility(benchmarkingUtility, "Signature Generation",
          benchmarkingTask, SignatureCreationController.this::handleBenchmarkingCompletion,
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

    if ((signatureModel.getNumTrials() == 0)
        || signatureModel.getPrivateKeyBatchLength() == 0
        || signatureModel.getSignatureType() == null
        || signatureModel.getCurrentFixedHashType_ComparisonMode() == null
        || signatureModel.getCurrentProvableHashType_ComparisonMode() == null) {
      uk.msci.project.rsa.DisplayUtility.showErrorAlert(
          "You must provide an input for all fields. Please try again.");
      return;
    }

    if (!setHashSizeInModel(signView)) {
      return;
    }
    benchmarkingUtility = new BenchmarkingUtility();
    Task<Void> benchmarkingTask = createBenchmarkingTaskComparisonMode(messageBatchFile);
    BenchmarkingUtility.beginBenchmarkWithUtility(benchmarkingUtility, "Signature Generation",
        benchmarkingTask,
        SignatureCreationController.this::handleBenchmarkingCompletionComparisonMode,
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
        signatureModel.batchCreateSignatures(messageFile, progress -> Platform.runLater(() -> {
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
        signatureModel.batchGenerateSignatures_ComparisonMode(messageFile,
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

    resultsController.showResultsView(mainController.getPrimaryStage(), keyConfigurationStrings,
        signatureModel.getClockTimesPerTrial(), signatureModel.getPrivKeyLengths(), true,
        signatureModel.getNumKeySizesForComparisonMode());
  }


  /**
   * Processes a file containing a batch of messages for signature creation. Validates the file's
   * content and updates the model and UI accordingly. Ensures the file format is correct (Ensures
   * the file format is correct i.e., no empty lines apart from the end of the file) and contains
   * the expected number of messages.
   *
   * @param file          The file containing messages to be signed.
   * @param signatureView The signature view to be updated with the imported batch.
   */
  public void handleMessageBatch(File file, SignatureBaseView signatureView) {
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
      signatureModel.setNumTrials(0);
      messageBatchFile = null;
      signView.setImportTextBatchBtnVisibility(true);
      signView.setCancelImportTextBatchButtonVisibility(false);
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
