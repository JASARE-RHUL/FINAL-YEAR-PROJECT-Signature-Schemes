package uk.msci.project.rsa;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javafx.application.Platform;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;


/**
 * This class serves as an abstract base for controllers managing the
 * display/interaction logic in
 * the benchmarking application and is designed to accommodate various
 * benchmarking scenarios,
 * including standard and comparison benchmarking modes. It is responsible
 * for managing various
 * aspects of results presentation such as tabulated results, graphical
 * representations, and
 * exporting functionalities.
 */
public abstract class ResultsBaseController {

  /**
   * The view component responsible for displaying the results.
   */
  ResultsView resultsView;

  /**
   * The model component holding and processing the benchmarking results.
   */
  ResultsModel resultsModel;

  /**
   * The main controller of the application, used for navigating back to the
   * main menu.
   */
  MainController mainController;

  /**
   * The current benchmarking context, which dictates the specific
   * benchmarking scenario.
   */
  BenchmarkingContext currentContext;

  /**
   * The list of key lengths used in the benchmarking process. Each integer
   * in the list represents
   * the length of a key in bits.
   */
  List<Integer> keyLengths;

  /**
   * The total number of trials conducted in the benchmarking process.
   */
  int totalTrials;


  /**
   * The total number of keys used in the benchmarking process.
   */
  int totalKeys;

  /**
   * A list containing all benchmarking results in a contiguous sequence,
   * ordered by keys.
   */
  List<Long> results;

  /**
   * The current key index being displayed in the results view.
   */
  int keyIndex;

  /**
   * A list of ResultsModel instances, each corresponding to results for a
   * specific key.
   */
  List<ResultsModel> resultsModels = new ArrayList<>();

  /**
   * Number of key sizes selected for comparison mode. This indicates how
   * many different key sizes
   * will be used to benchmark and compare provably secure versus standard
   * parameters.
   */
  int numKeySizesForComparisonMode;


  /**
   * The number of rows used in comparison mode.
   */
  int numRowsComparisonMode;


  /**
   * A list of row headers used in comparison mode, each representing a
   * distinct parameter type.
   */
  List<String> comparisonModeRowHeaders = new ArrayList<>();

  /**
   * Flag indicating whether the current results are from a signature operation.
   */
  boolean isSignatureOperationResults;

  /**
   * A mapping between key configurations and associated hash functions used
   * in the benchmarking
   * run.
   */
  Map<Integer, List<HashFunctionSelection>> keyConfigToHashFunctionsMap =
    new HashMap<>();

  /**
   * The total number of distinct groups of keys used in the benchmarking
   * process.
   */
  int totalGroups;

  /**
   * The number of keys per each distinct group in the benchmarking process.
   */
  int keysPerGroup;

  /**
   * An array representing the number of trials conducted per key for each
   * group in the benchmarking
   * process.
   */
  int[] trialsPerKeyByGroup;

  /**
   * The total number of hash functions used across all groups in the
   * benchmarking process.
   */
  int totalHashFunctions = 0;

  /**
   * Manages the creation and handling of various graphical representations
   * (like histograms, box
   * plots, and line graphs) of the benchmarking results. This includes
   * graphical analyses for both
   * individual key analysis and comparative analysis across different key
   * sizes and configurations.
   * The GraphManager supports a 'comparison mode' for side-by-side
   * performance comparison of
   * different key sizes and configurations using various graph types.
   */
  GraphManager graphManager;

  /**
   * Constructs a new ResultsController with a reference to the MainController.
   *
   * @param mainController The main controller of the application.
   */
  public ResultsBaseController(MainController mainController) {
    this.mainController = mainController;
  }

  /**
   * Loads and configures the results view with the provided benchmarking
   * results. This method
   * encapsulates common setup steps for displaying the results view,
   * including loading the FXML,
   * initialising the results controller, and setting up observers and
   * additional configurations
   * based on the benchmarking mode.
   *
   * @param keyLengths                 List of key lengths used in the
   *                                   benchmarking process.
   * @param results                    List of benchmarking results to display.
   * @param observerSetup              Runnable that sets up the observers
   *                                   for UI interactions.
   * @param additionalSetupBasedOnMode Runnable that contains additional
   *                                   setup steps specific to the
   *                                   current benchmarking mode.
   */
  void loadResultsView(List<Integer> keyLengths, List<Long> results,
                       Runnable observerSetup,
                       Runnable additionalSetupBasedOnMode) {
    try {
      FXMLLoader loader = new FXMLLoader(getClass().getResource("/ResultsView" +
        ".fxml"));
      Parent root = loader.load();
      resultsView = loader.getController();
      this.keyLengths = keyLengths;
      this.totalKeys = this.keyLengths.size();
      this.results = results;
      this.totalTrials = results.size();
      this.keyIndex = 0;
      numRowsComparisonMode = this.comparisonModeRowHeaders.size();
      if (!(currentContext instanceof KeyGenerationContext)) {
        isSignatureOperationResults = true;
      }
      this.graphManager = new GraphManager(totalTrials, totalKeys,
        numRowsComparisonMode,
        numKeySizesForComparisonMode,
        isSignatureOperationResults);

      displayCurrentContextButtons();

      graphManager.setLastSelectedGraphButton(resultsView.getHistogramButton());
      observerSetup.run();
      additionalSetupBasedOnMode.run();

      resultsModel = resultsModels.get(0);
      graphManager.setKeyIndex(keyIndex);
      setStatsResultsView(resultsModel, keyIndex); // Display results for the
      // first key by default
      resultsView.resizeTableView();
      setupObservers();

      mainController.setScene(root);
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  /**
   * Sets the benchmarking context for the results controller.
   *
   * @param context The benchmarking context to be used.
   */
  public void setContext(BenchmarkingContext context) {
    this.currentContext = context;
  }


  /**
   * Displays the results view, configured for either standard or comparison
   * mode. In standard mode,
   * this method initializes the results view with the provided benchmarking
   * results and prepares
   * the view based on the current benchmarking context. This includes
   * displaying statistical
   * results for each key, setting up key-specific navigation, and
   * configuring the UI for standard
   * results presentation.
   * <p>
   * In comparison mode, the view is configured to compare results across
   * multiple key sizes and
   * parameter sets (provably secure vs standard or any custom arrangement).
   * Takes an additional
   * parameter 'comparisonModeRowHeaders' which is a list of custom row
   * headers used in the results
   * table for comparison mode. These headers provide context for each row,
   * making the comparison
   * meaningful.
   *
   * @param results                      List of benchmarking results,
   *                                     ordered by keys. Each entry
   *                                     in the list represents the result of
   *                                     a benchmarking trial.
   * @param keyLengths                   List of key lengths used in the
   *                                     benchmarking process.
   * @param isComparisonMode             Flag indicating whether the
   *                                     comparison mode is active.
   * @param numKeySizesForComparisonMode Number of key sizes to be compared
   *                                     in comparison mode. This
   *                                     parameter is relevant only if
   *                                     'isComparisonMode' is true
   *                                     and dictates how the results are
   *                                     organized and displayed
   */
  public abstract void showResultsView(List<String> comparisonModeRowHeaders,
                                       List<Long> results,
                                       List<Integer> keyLengths,
                                       boolean isComparisonMode,
                                       int numKeySizesForComparisonMode);


  /**
   * Splits the benchmarking results by keys and associated hash functions,
   * creating a ResultsModel
   * for each unique combination. This method is used when benchmarking
   * signature operations.
   */
  void splitResults() {
    for (int keyIndex = 0; keyIndex < totalKeys; keyIndex++) {
      int startIndex = keyIndex * (this.totalTrials / totalKeys);
      int endIndex = startIndex + (this.totalTrials / totalKeys);
      List<Long> keySpecificResults = results.subList(startIndex, endIndex);
      ResultsModel resultsModel = new ResultsModel(keySpecificResults);
      if (isSignatureOperationResults) {
        setHashFunctionForModel(resultsModel);
      }
      resultsModel.calculateStatistics();
      resultsModels.add(resultsModel);
    }

  }

  /**
   * Sets the hash function information for the provided ResultsModel
   * instance. This method
   * calculates and assigns the appropriate hash function name and key length
   * to the model based on
   * the current benchmarking context.
   *
   * @param model The ResultsModel instance to be updated with hash function
   *              information.
   */
  public void setHashFunctionForModel(ResultsModel model) {
    int keyLength = keyLengths.get(keyIndex);
    model.setKeyLength(keyLength);
    int[] hashSizeFractions = currentContext.getCustomHashSizeFraction();
    if (currentContext.getProvablySecure()) {
      hashSizeFractions = new int[]{1, 2};
    }
    int digestSize = hashSizeFractions == null ? 0
      : (int) Math.round((keyLength * hashSizeFractions[0])
      / (double) hashSizeFractions[1]);
    String hashFunctionName =
      digestSize != 0 ? currentContext.getHashType().toString()
        + " (" + digestSize + "bit" + ")" :
        currentContext.getHashType().toString();
    model.setHashFunctionName(hashFunctionName);

  }

  /**
   * Displays the results for a specific key based on the given key index.
   *
   * @param keyIndex The index of the key for which results are to be displayed.
   */
  public abstract void displayResultsForKey(int keyIndex);

  /**
   * Configures the visibility and management of buttons in the results view
   * based on the current
   * benchmarking context.
   */
  public void displayCurrentContextButtons() {
    resultsView.setExportPrivateKeyBatchBtnVisible(
      currentContext.showExportPrivateKeyBatchButton());
    resultsView.setExportPrivateKeyBatchBtnManaged(
      currentContext.showExportPrivateKeyBatchButton());
    resultsView.setExportPublicKeyBatchBtnVisible(
      currentContext.showExportPublicKeyBatchButton());
    resultsView.setExportPublicKeyBatchBtnManaged(
      currentContext.showExportPublicKeyBatchButton());
    resultsView.setExportSignatureBatchBtnVisible(
      currentContext.showExportSignatureBatchButton());
    resultsView.setExportSignatureBatchBtnManaged(
      currentContext.showExportSignatureBatchButton());
    resultsView.setExportNonRecoverableMessageBatchBtVisible(
      currentContext.showNonRecoverableBatchButton());
    resultsView.setExportNonRecoverableMessageBatchBtnManaged(
      currentContext.showNonRecoverableBatchButton());
    resultsView.setExportVerificationResultsBtnVisible(
      currentContext.showExportVerificationResultsButton());
    resultsView.setExportVerificationResultsBtnManaged(
      currentContext.showExportVerificationResultsButton());
    if (isSignatureOperationResults && numKeySizesForComparisonMode > 0) {
      resultsView.setResultsLabel(currentContext.getResultsLabel(true));
    } else {
      resultsView.setResultsLabel(currentContext.getResultsLabel(false));
    }

  }

  /**
   * Sets up event observers for various actions in the results view, like
   * exporting results and
   * navigating back to the main menu.
   */
  public void setupObservers() {
    resultsView.addBackToMainMenuObserver(new BackToMainMenuObserver());
    resultsView.addExportPrivateKeyBatchObserver(new ExportPrivateKeyBatchObserver());
    resultsView.addExportPublicKeyBatchObserver(new ExportPublicKeyBatchObserver());
    resultsView.addExportSignatureBatchObserver(new ExportSignatureBatchObserver());
    resultsView.addExportNonRecoverableMessageBatchObserver(
      new ExportNonRecoverableMessageBatchObserver());
    resultsView.addExportVerificationResultsObserver(
      new ExportVerificationResultsObserver());
    resultsView.addKeyResultsChangeObserver(new KeyResultsChangeObserver());

  }


  /**
   * Sets statistical results in the results view based on the data from the
   * provided ResultsModel.
   *
   * @param model The ResultsModel instance containing statistical data to
   *              display.
   */
  public abstract void setStatsResultsView(ResultsModel model, int keyIndex);


  /**
   * Initialises the key results switch buttons in. This method sets up the
   * UI components that allow
   * the user to switch between results for different key sizes or keys.
   */
  abstract void initialiseKeySwitchButtons();


  /**
   * Observer for handling the export of benchmarking results. Triggers upon
   * user action to export
   * results to a CSV file.
   */
  class ExportBenchmarkingResultsObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
    }
  }

  /**
   * Observer for handling the export of verification results containing all
   * related data such keys,
   * signed messages, a boolean indicator of the results for each
   * verification etc. Triggers upon
   * user action to export results to a CSV file.
   */
  class ExportVerificationResultsObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
      try {
        currentContext.exportVerificationResults(keyIndex,
          keyLengths.get(keyIndex),
          mainController.getPrimaryStage());
      } catch (IOException e) {
        e.printStackTrace();
      }
    }
  }

  /**
   * Observer for handling key result changes. Updates the displayed results
   * based on the selected
   * key.
   */
  class KeyResultsChangeObserver implements ChangeListener<Number> {

    @Override
    public void changed(ObservableValue<? extends Number> observable,
                        Number oldValue,
                        Number newValue) {
      if (newValue != null) {
        displayResultsForKey(newValue.intValue());
        graphManager.displayLastSelectGraphForNewKeySize();
      }
    }
  }

  /**
   * Observer for handling the export of a private key batch. Triggers upon
   * user action to export
   * the private key batch.
   */
  class ExportPrivateKeyBatchObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
      try {
        currentContext.exportPrivateKeyBatch();
        uk.msci.project.rsa.DisplayUtility.showInfoAlert("Export",
          "The private key batch was successfully exported!");
      } catch (IOException e) {
        e.printStackTrace();
      }
    }
  }

  /**
   * Observer for handling the export of a public key batch. Triggers upon
   * user action to export the
   * public key batch.
   */
  class ExportPublicKeyBatchObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
      try {
        currentContext.exportPublicKeyBatch();
        uk.msci.project.rsa.DisplayUtility.showInfoAlert("Export",
          "The public key batch was successfully exported!");
      } catch (IOException e) {
        e.printStackTrace();
      }
    }
  }

  /**
   * Observer for handling the export of a signature batch. Triggers upon
   * user action to export the
   * signature batch.
   */
  class ExportSignatureBatchObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
      Platform.runLater(() -> {
        try {
          currentContext.exportSignatureBatch();
          uk.msci.project.rsa.DisplayUtility.showInfoAlert("Export",
            "The signature batch was successfully exported. Warning: The " +
              "Signature batch is inclusive of signatures corresponding to " +
              "all keys submitted for this session");
        } catch (IOException e) {
          uk.msci.project.rsa.DisplayUtility.showErrorAlert(
            "Error: signature batch could not be exported");
        }
      });

    }

    /**
     * Observer for handling the export of a non-Recoverable Message batch.
     * Triggers upon user action
     * to export the non-Recoverable batch.
     */
    class ExportNonRecoverableMessageBatchObserver implements EventHandler<ActionEvent> {

      @Override
      public void handle(ActionEvent event) {
        Platform.runLater(() -> {
          try {
            currentContext.exportNonRecoverableMessages();
            uk.msci.project.rsa.DisplayUtility.showInfoAlert("Export",
              "The non-recoverable message batch was successfully exported!");
          } catch (IOException e) {
            uk.msci.project.rsa.DisplayUtility.showErrorAlert(
              "Error: non-recoverable message batch could not be exported");
          }
        });
      }
    }


    /**
     * The observer for returning to the main menu. This class handles the
     * action event triggered when
     * the user wishes to return to the main menu from the results view.
     */
    class BackToMainMenuObserver implements EventHandler<ActionEvent> {

      @Override
      public void handle(ActionEvent event) {
        mainController.showMainMenuView();
        currentContext = null;
        resultsModel = null;
        resultsModels = null;
        keyLengths = null;
        results = null;
        resultsView = null;
      }
    }


  }
