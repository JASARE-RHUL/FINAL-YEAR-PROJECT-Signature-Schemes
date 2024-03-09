package uk.msci.project.rsa;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXMLLoader;
import javafx.geometry.Pos;
import javafx.scene.Parent;
import javafx.scene.control.Label;
import javafx.scene.control.Tab;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;


/**
 * This class manages the results display and interaction logic for the digital signature
 * benchmarking application. It integrates the results view and model, handles the generation of
 * result statistics, and manages the export functionalities.
 */
public class ResultsController {

  /**
   * The view component responsible for displaying the results.
   */
  private ResultsView resultsView;

  /**
   * The model component holding and processing the benchmarking results.
   */
  private ResultsModel resultsModel;

  /**
   * The main controller of the application, used for navigating back to the main menu.
   */
  private MainController mainController;

  /**
   * The current benchmarking context, which dictates the specific benchmarking scenario.
   */
  private BenchmarkingContext currentContext;

  /**
   * The list of key lengths used in the benchmarking process. Each integer in the list represents
   * the length of a key in bits.
   */
  private List<Integer> keyLengths;

  /**
   * The total number of trials conducted in the benchmarking process.
   */
  private int totalTrials;


  /**
   * The total number of keys used in the benchmarking process.
   */
  private int totalKeys;

  /**
   * A list containing all benchmarking results in a contiguous sequence, ordered by keys.
   */
  private List<Long> results;

  /**
   * The current key index being displayed in the results view.
   */
  private int keyIndex;

  /**
   * A list of ResultsModel instances, each corresponding to results for a specific key.
   */
  private List<ResultsModel> resultsModels = new ArrayList<>();

  /**
   * Number of key sizes selected for comparison mode. This indicates how many different key sizes
   * will be used to benchmark and compare provably secure versus standard parameters.
   */
  private int numKeySizesForComparisonMode;


  /**
   * The number of rows used in comparison mode.
   */
  private int numRowsComparisonMode;


  /**
   * A list of row headers used in comparison mode, each representing a distinct parameter type.
   */
  private List<String> comparisonModeRowHeaders = new ArrayList<>();

  /**
   * Flag indicating whether the current results are from a signature operation.
   */
  private boolean isSignatureOperationResults;

  /**
   * A mapping between key configurations and associated hash functions used in the benchmarking
   * run.
   */
  private Map<Integer, List<HashFunctionSelection>> keyConfigToHashFunctionsMap = new HashMap<>();

  /**
   * The total number of distinct groups of keys used in the benchmarking process.
   */
  private int totalGroups;

  /**
   * The number of keys per each distinct group in the benchmarking process.
   */
  private int keysPerGroup;

  /**
   * An array representing the number of trials conducted per key for each group in the benchmarking
   * process.
   */
  private int[] trialsPerKeyByGroup;

  /**
   * The total number of hash functions used across all groups in the benchmarking process.
   */
  private int totalHashFunctions = 0;

  /**
   * Manages the creation and handling of various graphical representations (like histograms, box
   * plots, and line graphs) of the benchmarking results. This includes graphical analyses for both
   * individual key analysis and comparative analysis across different key sizes and configurations.
   * The GraphManager supports a 'comparison mode' for side-by-side performance comparison of
   * different key sizes and configurations using various graph types.
   */
  private GraphManager graphManager;

  /**
   * Constructs a new ResultsController with a reference to the MainController.
   *
   * @param mainController The main controller of the application.
   */
  public ResultsController(MainController mainController) {
    this.mainController = mainController;
  }

  /**
   * Loads and configures the results view with the provided benchmarking results. This method
   * encapsulates common setup steps for displaying the results view, including loading the FXML,
   * initializing the results controller, and setting up observers and additional configurations
   * based on the benchmarking mode.
   *
   * @param keyLengths                 List of key lengths used in the benchmarking process.
   * @param results                    List of benchmarking results to display.
   * @param observerSetup              Runnable that sets up the observers for UI interactions.
   * @param additionalSetupBasedOnMode Runnable that contains additional setup steps specific to the
   *                                   current benchmarking mode.
   */
  private void loadResultsView(List<Integer> keyLengths, List<Long> results,
      Runnable observerSetup,
      Runnable additionalSetupBasedOnMode) {
    try {
      FXMLLoader loader = new FXMLLoader(getClass().getResource("/ResultsView.fxml"));
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
      this.graphManager = new GraphManager(totalTrials, totalKeys, numRowsComparisonMode,
          numKeySizesForComparisonMode,
          isSignatureOperationResults);


      displayCurrentContextButtons();

      graphManager.setLastSelectedGraphButton(resultsView.getHistogramButton());
      observerSetup.run();
      additionalSetupBasedOnMode.run();

      resultsModel = resultsModels.get(0);
      graphManager.setKeyIndex(keyIndex);
      setStatsResultsView(resultsModel, keyIndex); // Display results for the first key by default
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
   * Displays the results view in standard mode and initialises the results model with the provided
   * benchmarking results. This method prepares the results view by configuring it based on the
   * current benchmarking context, including the display of statistical results for each key. It
   * also sets up key-specific navigation within the view, allowing the user to switch between
   * results for different keys.
   *
   * @param primaryStage The primary stage on which the results view is to be set. This is the main
   *                     window of the application where the results view will be displayed.
   * @param results      List of all benchmarking results, ordered by keys.
   * @param keyLengths   The list of key lengths, in bits, used in the benchmarking process. Each
   *                     length in this list corresponds to a set of results in the 'results' list.
   *                     This parameter is essential for categorising the results by key length and
   *                     setting up the key-specific views.
   */
  public void showResultsView(Stage primaryStage, List<Long> results, List<Integer> keyLengths) {
    loadResultsView(keyLengths, results,
        () -> graphManager.setupComparisonModeGraphObservers(resultsView),
        () -> {
          resultsView.setupTableView();
          resultsView.populateTableView();
          initialiseKeySwitchButtons();
          splitResultsByKeys();
          if (isSignatureOperationResults) {
            resultsView.addStatisticData(
                new StatisticData("Hash Function:", resultsModels.get(0).getHashFunctionName()));
          }
          resultsView.refreshResults();
          graphManager.precomputeGraphs(resultsModels, keyLengths);
          resultsView.setLineGraphButtonMeanVisibility(false);
        });
  }


  /**
   * Displays the results view, configured for either standard or comparison mode. In standard mode,
   * this method initializes the results view with the provided benchmarking results and prepares
   * the view based on the current benchmarking context. This includes displaying statistical
   * results for each key, setting up key-specific navigation, and configuring the UI for standard
   * results presentation.
   * <p>
   * In comparison mode, the view is configured to compare results across multiple key sizes and
   * parameter sets (provably secure vs standard or any custom arrangement). Takes an additional
   * parameter 'comparisonModeRowHeaders' which is a list of custom row headers used in the results
   * table for comparison mode. These headers provide context for each row, making the comparison
   * meaningful.
   *
   * @param primaryStage                 The primary stage where the results view is to be
   *                                     displayed. This is the main window of the application.
   * @param results                      List of benchmarking results, ordered by keys. Each entry
   *                                     in the list represents the result of a benchmarking trial.
   * @param keyLengths                   List of key lengths used in the benchmarking process.
   * @param isComparisonMode             Flag indicating whether the comparison mode is active.
   * @param numKeySizesForComparisonMode Number of key sizes to be compared in comparison mode. This
   *                                     parameter is relevant only if 'isComparisonMode' is true
   *                                     and dictates how the results are organized and displayed
   *                                     for comparative analysis.
   */
  public void showResultsView(Stage primaryStage, List<String> comparisonModeRowHeaders,
      List<Long> results, List<Integer> keyLengths,
      boolean isComparisonMode, int numKeySizesForComparisonMode) {
    if (!isComparisonMode) {
      showResultsView(primaryStage, results, keyLengths);
      return;
    }
    this.comparisonModeRowHeaders = comparisonModeRowHeaders;
    this.numKeySizesForComparisonMode = numKeySizesForComparisonMode;
    loadResultsView(keyLengths, results,
        () -> graphManager.setupComparisonModeGraphObservers(resultsView),
        () -> {
          resultsView.removeValueColumn();
          resultsView.setNameColumnText("Parameter Type");
          if (isSignatureOperationResults) {
            keyConfigToHashFunctionsMap = currentContext.getKeyConfigToHashFunctionsMap();
            totalGroups = currentContext.getTotalGroups();
            keysPerGroup = currentContext.getKeysPerGroup();
            totalHashFunctions = currentContext.getTotalHashFunctions();
            trialsPerKeyByGroup = currentContext.getTrialsPerKeyByGroup();
            splitResultsByKeysSignatures();
          } else {
            splitResultsByKeys();
          }
          initialiseKeySwitchButtonsComparisonMode();
          resultsView.addValueColumns(createComparisonModeColumnHeaders());

          graphManager.precomputeGraphsComparisonMode(resultsModels, comparisonModeRowHeaders,
              results, keyLengths);

        });
  }


  /**
   * Updates the column headers (These headers correspond to different statistics that will be
   * compared) for the benchmarking results table view in comparison mode. Adds a specific column
   * for 'Hash Function' if the current results are from a signature operation.
   *
   * @return A list of ResultsTableColumn objects initialized with header titles.
   */
  private List<ResultsTableColumn> createComparisonModeColumnHeaders() {
    List<ResultsTableColumn> resultsTableColumnList = new ArrayList<>();
    if (isSignatureOperationResults) {
      resultsTableColumnList.add(new ResultsTableColumn("Hash Function"));
    }
    resultsTableColumnList.add(new ResultsTableColumn("Trials"));
    resultsTableColumnList.add(new ResultsTableColumn("Overall time"));
    resultsTableColumnList.add(new ResultsTableColumn("Mean"));
    resultsTableColumnList.add(new ResultsTableColumn("Std Dev"));
    resultsTableColumnList.add(new ResultsTableColumn("Variance"));
    resultsTableColumnList.add(new ResultsTableColumn("Conf. Interval"));
    resultsTableColumnList.add(new ResultsTableColumn("25th Percentile"));
    resultsTableColumnList.add(new ResultsTableColumn("Median"));
    resultsTableColumnList.add(new ResultsTableColumn("75th Percentile"));
    resultsTableColumnList.add(new ResultsTableColumn("Range"));
    resultsTableColumnList.add(new ResultsTableColumn("Min"));
    resultsTableColumnList.add(new ResultsTableColumn("Max"));
    return resultsTableColumnList;
  }


  /**
   * Splits the benchmarking results by keys and associated hash functions, creating a ResultsModel
   * for each unique combination. This method is used when benchmarking signature operations.
   */
  private void splitResultsByKeysSignatures() {
    resultsModels.clear();
    int currentIndex = 0;
    int headerStartIndex = 0; // Starting index for the row headers for each group
    int resultsPerKeySize = totalTrials / numKeySizesForComparisonMode;

    while (currentIndex < results.size()) {
      for (int groupIndex = 0; groupIndex < totalGroups; groupIndex++) {
        List<HashFunctionSelection> hashFunctions = keyConfigToHashFunctionsMap.get(groupIndex);

        for (int hashFunctionIndex = 0; hashFunctionIndex < hashFunctions.size();
            hashFunctionIndex++) {
          for (int k = 0; k < keysPerGroup; k++) {
            int keyIndex =
                groupIndex * keysPerGroup + k
                    + (totalGroups * keysPerGroup) * (Math.floorDiv(currentIndex,
                    resultsPerKeySize));
            if (keyIndex >= totalKeys) {
              break; // Prevent accessing keys beyond the total number of keys
            }

            int trialsPerHashFunction = trialsPerKeyByGroup[groupIndex] / hashFunctions.size();
            List<Long> keySpecificResults = results.subList(currentIndex,
                currentIndex + trialsPerHashFunction);

            String keyConfigString = comparisonModeRowHeaders.get(
                (headerStartIndex + k) % comparisonModeRowHeaders.size());
            int keyLength = keyLengths.get(keyIndex); // Retrieve the key length
            HashFunctionSelection currentHashFunction = hashFunctions.get(hashFunctionIndex);
            int[] hashSizeFractions = currentHashFunction.getCustomSize();
            if (currentHashFunction.isProvablySecure()) {
              hashSizeFractions = new int[]{1, 2};
            }
            int digestSize = hashSizeFractions == null ? 0
                : (int) Math.round((keyLength * hashSizeFractions[0])
                    / (double) hashSizeFractions[1]);

            String hashFunctionName =
                digestSize != 0 ? currentHashFunction.getDigestType().toString()
                    + " (" + digestSize + "bit" + ")"
                    : currentHashFunction.getDigestType().toString();
            ResultsModel resultsModel = new ResultsModel(keySpecificResults, keyConfigString,
                hashFunctionName, keyLength);
            resultsModel.calculateStatistics();
            resultsModels.add(resultsModel);

            currentIndex += trialsPerHashFunction;
          }
        }
        headerStartIndex += keysPerGroup; // Move to the next set of headers for the next group
      }
    }
  }


  /**
   * Splits the results into groups based on keys and creates a ResultsModel for each group.
   */
  private void splitResultsByKeys() {
    for (int keyIndex = 0; keyIndex < totalKeys; keyIndex++) {
      int startIndex = keyIndex * (this.totalTrials / totalKeys);
      int endIndex = startIndex + (this.totalTrials / totalKeys);
      List<Long> keySpecificResults = results.subList(startIndex, endIndex);
      ResultsModel resultsModel = new ResultsModel(keySpecificResults);
      if (isSignatureOperationResults) {
        int keyLength = keyLengths.get(keyIndex);
        resultsModel.setKeyLength(keyLength);
        int[] hashSizeFractions = currentContext.getCustomHashSizeFraction();
        if (currentContext.getProvablySecure()) {
          hashSizeFractions = new int[]{1, 2};
        }
        int digestSize = hashSizeFractions == null ? 0
            : (int) Math.round((keyLength * hashSizeFractions[0])
                / (double) hashSizeFractions[1]);
        String hashFunctionName =
            digestSize != 0 ? currentContext.getHashType().toString()
                + " (" + digestSize + "bit" + ")" : currentContext.getHashType().toString();
        resultsModel.setHashFunctionName(hashFunctionName);
      }
      resultsModel.calculateStatistics();
      resultsModels.add(resultsModel);
    }

  }

  /**
   * Displays the results for a specific key based on the given key index.
   *
   * @param keyIndex The index of the key for which results are to be displayed.
   */
  public void displayResultsForKey(int keyIndex) {
    this.keyIndex = keyIndex;
    graphManager.setKeyIndex(keyIndex);
    resultsModel = resultsModels.get(keyIndex);
    resultsView.removeLastRow();
    resultsView.addStatisticData(
        new StatisticData("Hash Function:", resultsModel.getHashFunctionName()));
    setStatsResultsView(resultsModel, keyIndex);
  }

  /**
   * Configures the visibility and management of buttons in the results view based on the current
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
   * Sets up event observers for various actions in the results view, like exporting results and
   * navigating back to the main menu.
   */
  public void setupObservers() {
    resultsView.addBackToMainMenuObserver(new BackToMainMenuObserver());
    resultsView.addExportBenchmarkingResultsObserver(new ExportBenchmarkingResultsObserver());
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
   * Sets statistical results in the results view based on the data from the provided ResultsModel.
   *
   * @param model The ResultsModel instance containing statistical data to display.
   */
  public void setStatsResultsView(ResultsModel model, int keyIndex) {

    if (numKeySizesForComparisonMode > 0) {
      // Handle comparison mode: each StatisticData should have multiple values
      resultsView.clearTableView();
      for (StatisticData data : prepareComparisonData(keyIndex)) {
        resultsView.addStatisticData(data);
      }
    } else {
      resultsView.setNumTrials(String.valueOf(model.getNumTrials()));
      resultsView.setMeanValue(String.format("%.5f ms", model.getMeanData()));
      resultsView.setPercentile25Value(String.format("%.5f ms", model.getPercentile25Data()));
      resultsView.setMedianValue(String.format("%.5f ms", model.getMedianData()));
      resultsView.setPercentile75Value(String.format("%.5f ms", model.getPercentile75Data()));
      resultsView.setRangeValue(String.format("%.5f ms", model.getRangeData()));
      resultsView.setStdDeviationValue(String.format("%.5f ms", model.getStdDeviationData()));
      resultsView.setVarianceValue(String.format("%.5f ms²", model.getVarianceData()));
      resultsView.setMinTimeValue(String.format("%.5f ms", model.getMinTimeData()));
      resultsView.setMaxTimeValue(String.format("%.5f ms", model.getMaxTimeData()));
      resultsView.setOverallData(String.format("%.5f ms", model.getOverallData()));

      double[] confidenceInterval = model.getConfidenceInterval();
      String confidenceIntervalStr = String.format(
          "95%% with bounds [%.5f, %.5f]",
          confidenceInterval[0],
          confidenceInterval[1]
      );
      resultsView.setConfidenceInterval(confidenceIntervalStr);
    }

    resultsView.refreshResults();
  }


  /**
   * Prepares the comparison mode data for display in the results view. The method organises data
   * based on the key index and formats it for the comparison table.
   *
   * @param keyIndex The index of the key size for which the data is prepared.
   * @return A list of StatisticData objects containing the formatted data for comparison mode.
   */
  private List<StatisticData> prepareComparisonData(int keyIndex) {
    List<StatisticData> comparisonData = new ArrayList<>();

    // Calculate start and end index for the range of models related to this key size
    int startKeyIndex = keyIndex * (resultsModels.size() / numKeySizesForComparisonMode);
    int endKeyIndex = (keyIndex + 1) * (resultsModels.size() / numKeySizesForComparisonMode);

    for (int modelIndex = startKeyIndex; modelIndex < endKeyIndex; modelIndex++) {
      ResultsModel model = resultsModels.get(modelIndex);
      List<String> parameterRow = new ArrayList<>();

      String rowHeader;
      if (isSignatureOperationResults) {
        rowHeader = model.getConfigString();
        parameterRow.add(model.getHashFunctionName());
      } else {
        // Use the regular comparison row headers if not a signature operation
        rowHeader = comparisonModeRowHeaders.get(modelIndex % comparisonModeRowHeaders.size());
      }

      // Add statistics data to the parameter row
      parameterRow.add(String.valueOf(model.getNumTrials()));
      parameterRow.add(String.format("%.5f ms", model.getOverallData()));
      parameterRow.add(String.format("%.5f ms", model.getMeanData()));
      parameterRow.add(String.format("%.5f ms", model.getStdDeviationData()));
      parameterRow.add(String.format("%.5f ms²", model.getVarianceData()));
      double[] confidenceInterval = model.getConfidenceInterval();
      parameterRow.add(
          String.format("95%% with bounds [%.5f, %.5f]", confidenceInterval[0],
              confidenceInterval[1])
      );
      parameterRow.add(String.format("%.5f ms", model.getPercentile25Data()));
      parameterRow.add(String.format("%.5f ms", model.getMedianData()));
      parameterRow.add(String.format("%.5f ms", model.getPercentile75Data()));
      parameterRow.add(String.format("%.5f ms", model.getRangeData()));
      parameterRow.add(String.format("%.5f ms", model.getMinTimeData()));
      parameterRow.add(String.format("%.5f ms", model.getMaxTimeData()));

      // Add this row of data to the comparison data list
      comparisonData.add(new StatisticData(rowHeader, parameterRow));
    }

    return comparisonData;
  }


  /**
   * Initialises the key switch buttons in comparison mode. This method sets up the UI components
   * that allow the user to switch between results (standard vs provable parameters) for different
   * key sizes.
   */
  private void initialiseKeySwitchButtonsComparisonMode() {
    for (int i = 0; i < numKeySizesForComparisonMode; i++) {
      int keySizeIndex = i;
      Tab keyTab = new Tab();

      // Create the ImageView for the key image
      ImageView imageView = new ImageView(new Image("keyImg.png"));
      imageView.setFitHeight(90);
      imageView.setFitWidth(90);
      imageView.setPickOnBounds(true);
      imageView.setPreserveRatio(true);

      // Create the label with the key number
      Label keyLabel = new Label(
          "Key Size " + (keySizeIndex + 1) + " (" + ResultsUtility.getKeyLength(keySizeIndex,
              resultsModels, numKeySizesForComparisonMode, keyLengths)
              + "bit)");

      // Create a VBox to hold the ImageView and Label
      VBox graphicBox = new VBox(imageView, keyLabel);
      graphicBox.setAlignment(Pos.CENTER);

      // Set the graphic of the tab
      keyTab.setGraphic(graphicBox);

      resultsView.addKeySwitchTab(keyTab);
    }

  }

  /**
   * Initialises the key switch buttons for the standard results mode. This method sets up the UI
   * components that allow the user to switch between results for different keys.
   */
  private void initialiseKeySwitchButtons() {
    for (int i = 0; i < totalKeys; i++) {
      int keyIndex = i;
      Tab keyTab = new Tab();

      // Create the ImageView for the key image
      ImageView imageView = new ImageView(new Image("keyImg.png"));
      imageView.setFitHeight(90);
      imageView.setFitWidth(90);
      imageView.setPickOnBounds(true);
      imageView.setPreserveRatio(true);

      // Create the label with the key number
      Label keyLabel = new Label(
          "Key " + (keyIndex + 1) + " (" + keyLengths.get(keyIndex) + "bit)");

      // Create a VBox to hold the ImageView and Label
      VBox graphicBox = new VBox(imageView, keyLabel);
      graphicBox.setAlignment(Pos.CENTER);

      // Set the graphic of the tab
      keyTab.setGraphic(graphicBox);

      resultsView.addKeySwitchTab(keyTab);
    }

  }

  /**
   * Observer for handling the export of benchmarking results. Triggers upon user action to export
   * results to a CSV file.
   */
  class ExportBenchmarkingResultsObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
      try {
        if (numKeySizesForComparisonMode == 0) {
          resultsModel.exportStatisticsToCSV(
              currentContext.getResultsLabel(true) + "_" + keyLengths.get(keyIndex) + "bit.csv");
        } else {
          resultsView.exportComparisonTableResultsToCSV(
              currentContext.getResultsLabel(false) + "_" + ResultsUtility.getKeyLength(keyIndex,
                  resultsModels, numKeySizesForComparisonMode, keyLengths) + "bit_key"
                  + "_comparisonMode.csv");
        }
        uk.msci.project.rsa.DisplayUtility.showInfoAlert("Export",
            "Benchmarking Results were successfully exported!");
      } catch (IOException e) {
        e.printStackTrace();
      }
    }
  }

  /**
   * Observer for handling the export of verification results containing all related data such keys,
   * signed messages, a boolean indicator of the results for each verification etc. Triggers upon
   * user action to export results to a CSV file.
   */
  class ExportVerificationResultsObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
      try {
        currentContext.exportVerificationResults(keyIndex);
      } catch (IOException e) {
        e.printStackTrace();
      }
      uk.msci.project.rsa.DisplayUtility.showInfoAlert("Export",
          "Verification Results were successfully exported!");
    }
  }

  /**
   * Observer for handling key result changes. Updates the displayed results based on the selected
   * key.
   */
  class KeyResultsChangeObserver implements ChangeListener<Number> {

    @Override
    public void changed(ObservableValue<? extends Number> observable, Number oldValue,
        Number newValue) {
      if (newValue != null) {
        displayResultsForKey(newValue.intValue());
        graphManager.displayLastSelectGraphForNewKeySize();
      }
    }
  }

  /**
   * Observer for handling the export of a private key batch. Triggers upon user action to export
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
   * Observer for handling the export of a public key batch. Triggers upon user action to export the
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
   * Observer for handling the export of a signature batch. Triggers upon user action to export the
   * signature batch.
   */
  class ExportSignatureBatchObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
      try {
        currentContext.exportSignatureBatch();
        uk.msci.project.rsa.DisplayUtility.showInfoAlert("Export",
            "The signature batch was successfully exported. Warning: The Signature batch is inclusive of signatures corresponding to all keys submitted for this session");
      } catch (IOException e) {
        e.printStackTrace();
      }
    }
  }

  /**
   * Observer for handling the export of a non-Recoverable Message batch. Triggers upon user action
   * to export the non-Recoverable batch.
   */
  class ExportNonRecoverableMessageBatchObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
      try {
        currentContext.exportNonRecoverableMessages();
        uk.msci.project.rsa.DisplayUtility.showInfoAlert("Export",
            "The non-recoverable message batch was successfully exported!");
      } catch (IOException e) {
        e.printStackTrace();
      }
    }
  }


  /**
   * The observer for returning to the main menu. This class handles the action event triggered when
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
