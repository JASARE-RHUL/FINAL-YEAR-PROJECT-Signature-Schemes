package uk.msci.project.rsa;

import java.awt.Color;
import java.awt.Font;
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
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.Tab;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;
import javafx.util.Pair;
import org.jfree.chart.ChartFactory;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.axis.CategoryAxis;
import org.jfree.chart.axis.CategoryLabelPositions;
import org.jfree.chart.axis.NumberAxis;
import org.jfree.chart.axis.SymbolAxis;
import org.jfree.chart.fx.ChartViewer;
import org.jfree.chart.plot.CategoryPlot;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.chart.plot.XYPlot;
import org.jfree.chart.renderer.category.StackedBarRenderer;
import org.jfree.chart.renderer.xy.XYErrorRenderer;
import org.jfree.chart.renderer.xy.XYLineAndShapeRenderer;
import org.jfree.data.category.CategoryDataset;
import org.jfree.data.category.DefaultCategoryDataset;
import org.jfree.data.statistics.BoxAndWhiskerItem;
import org.jfree.data.statistics.DefaultBoxAndWhiskerCategoryDataset;
import org.jfree.data.xy.XYSeries;
import org.jfree.data.xy.XYSeriesCollection;
import org.jfree.data.xy.YIntervalSeries;
import org.jfree.data.xy.YIntervalSeriesCollection;


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
   * Stores precomputed graph views to avoid re-rendering for each view request.
   */
  private Map<String, ChartViewer> precomputedGraphs;

  /**
   * Stores the last selected graph button to maintain the active state across different result
   * sets.
   */
  private Button lastSelectedGraphButton;

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
   * Constructs a new ResultsController with a reference to the MainController.
   *
   * @param mainController The main controller of the application.
   */
  public ResultsController(MainController mainController) {
    this.mainController = mainController;
    precomputedGraphs = new HashMap<String, ChartViewer>();
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
      if (!(currentContext instanceof KeyGenerationContext)) {
        isSignatureOperationResults = true;
      }

      displayCurrentContextButtons();

      observerSetup.run();
      additionalSetupBasedOnMode.run();

      resultsModel = resultsModels.get(0);
      setStatsResultsView(resultsModel, keyIndex); // Display results for the first key by default
      resultsView.resizeTableView();
      lastSelectedGraphButton = resultsView.getHistogramButton();
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
    loadResultsView(keyLengths, results, this::setupCommonGraphObservers,
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
          precomputeGraphs();
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
    numRowsComparisonMode = this.comparisonModeRowHeaders.size();
    this.numKeySizesForComparisonMode = numKeySizesForComparisonMode;
    loadResultsView(keyLengths, results, this::setupComparisonModeGraphObservers,
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

          precomputeGraphsComparisonMode();

        });
  }

  /**
   * Precomputes and stores graphs for all keys to optimise performance during graph switching.
   */
  private void precomputeGraphs() {
    for (int keyIndex = 0; keyIndex < totalKeys; keyIndex++) {
      // Precompute and store each type of graph for each key
      String histogramKey = "Histogram_" + keyIndex;
      precomputedGraphs.put(histogramKey, displayHistogramForKey(keyIndex));

      String boxPlotKey = "BoxPlot_" + keyIndex;
      ChartViewer boxPlotViewer = displayBoxPlotForKey(keyIndex);
      precomputedGraphs.put(boxPlotKey, boxPlotViewer);

    }
  }

  /**
   * Precomputes and stores graphs for comparison mode, facilitating quick switching between
   * graphs.
   */
  private void precomputeGraphsComparisonMode() {
    for (int keySizeIndex = 0; keySizeIndex < numKeySizesForComparisonMode; keySizeIndex++) {
      // Precompute and store each type of graph for each key
      String histogramKey = "Histogram_" + keySizeIndex;
      precomputedGraphs.put(histogramKey, displayStackedHistogram(keySizeIndex));

      String lineChartMeanKey = "LineChartMeanTimes_" + keySizeIndex;
      ChartViewer lineChartMeanViewer = displayLineGraphMeanForComparisonMode(keySizeIndex);
      precomputedGraphs.put(lineChartMeanKey, lineChartMeanViewer);

      String boxPlotKey = "BoxPlot_" + keySizeIndex;
      ChartViewer boxPlotViewer = displayBoxPlotForComparisonMode(keySizeIndex);
      precomputedGraphs.put(boxPlotKey, boxPlotViewer);

    }
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

    while (currentIndex < results.size()) {
      for (int groupIndex = 0; groupIndex < totalGroups; groupIndex++) {
        List<HashFunctionSelection> hashFunctions = keyConfigToHashFunctionsMap.get(groupIndex);

        for (int hashFunctionIndex = 0; hashFunctionIndex < hashFunctions.size();
            hashFunctionIndex++) {
          for (int k = 0; k < keysPerGroup; k++) {
            int keyIndex = groupIndex * keysPerGroup + k;
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
   * Sets up observers for graph buttons common to both comparison and non comparison mode.
   */
  public void setupCommonGraphObservers() {
    resultsView.addHistogramButtonObserver(new HistogramButtonObserver());
    resultsView.addBoxPlotButtonObserver(new BoxPlotButtonObserver());
  }

  /**
   * Sets up observers specifically for the graph buttons in comparison mode.
   */
  public void setupComparisonModeGraphObservers() {
    setupCommonGraphObservers();
    resultsView.addLineGraphButtonMeanObserver(new LineGraphButtonMeanObserver());
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
      // Calculate the starting model index for this key size
      int startModelIndex = keySizeIndex * (resultsModels.size() / numKeySizesForComparisonMode);

      // Create the label with the key number
      Label keyLabel = new Label(
          "Key Size " + (keySizeIndex + 1) + " (" + keyLengths.get(
              startModelIndex % keyLengths.size()) + "bit)");

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
   * Observer for displaying a histogram view of results for the current key/key size.
   */
  class HistogramButtonObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
      String histogramKey = "Histogram_" + keyIndex;
      ChartViewer viewer = precomputedGraphs.get(histogramKey);
      resultsView.updateGraphArea(viewer);
      lastSelectedGraphButton = resultsView.histogramButton;
    }
  }


  /**
   * Observer for displaying a box plot graph view composed of relevant statistical averages from
   * the results for the current key/key size.
   */
  class BoxPlotButtonObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
      String boxPlotKey = "BoxPlot_" + keyIndex;
      ChartViewer viewer = precomputedGraphs.get(boxPlotKey);
      resultsView.updateGraphArea(viewer);
      lastSelectedGraphButton = resultsView.getBoxPlotButton();
    }
  }

  /**
   * Observer for displaying a line graph view with mean times from the results for the current key
   * size in comparison mode.
   */
  class LineGraphButtonMeanObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
      String lineChartMeanKey = "LineChartMeanTimes_" + keyIndex;
      ChartViewer viewer = precomputedGraphs.get(lineChartMeanKey);
      resultsView.updateGraphArea(viewer);
      lastSelectedGraphButton = resultsView.getLineGraphButtonMean();

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
          int startModelIndex = keyIndex * (resultsModels.size() / numKeySizesForComparisonMode);
          resultsView.exportComparisonTableResultsToCSV(
              currentContext.getResultsLabel(false) + "_" + keyLengths.get(
                  startModelIndex % keyLengths.size()) + "bit_key" + "_comparisonMode.csv");
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
        lastSelectedGraphButton.fire();
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


  /**
   * Calculates the bin width using the Freedman-Diaconis rule.
   *
   * @param keyIndex The index of the key to calculate the bin width for.
   * @param results  The results to use in the calculation.
   * @return The calculated bin width.
   */
  private double calculateFreedmanDiaconisBinWidth(int keyIndex, List<Long> results) {
    double q1 = BenchmarkingUtility.calculatePercentile(results, 0.25);
    double q3 = BenchmarkingUtility.calculatePercentile(results, 0.75);
    double iqr = (q3 - q1) / 1E6;
    return 2 * iqr * Math.pow(results.size(), -1 / 3.0);
  }

  /**
   * Calculates the number of bins for a histogram based on the given results.
   *
   * @param keyIndex The index of the key to calculate the number of bins for.
   * @param results  The results to use in the calculation.
   * @return The number of bins.
   */
  private int calculateNumberOfBins(int keyIndex, List<Long> results) {
    double min = BenchmarkingUtility.getMin(results) / 1E6;
    double max = BenchmarkingUtility.getMax(results) / 1E6;
    return (int) Math.ceil((max - min) / calculateFreedmanDiaconisBinWidth(keyIndex, results));
  }

  /**
   * Creates a dataset for a stacked histogram, specific to signature operations, given a key size
   * index.
   *
   * @param keySizeIndex Index of the key for which the dataset is prepared.
   * @return A CategoryDataset suitable for creating a stacked histogram.
   */
  private CategoryDataset createStackedHistogramDatasetSignatures(int keySizeIndex) {
    DefaultCategoryDataset dataset = new DefaultCategoryDataset();

    // Calculate the range of model indices for the specified key size
    int startModelIndex = keySizeIndex * (resultsModels.size() / numKeySizesForComparisonMode);
    int endModelIndex = (keySizeIndex + 1) * (resultsModels.size() / numKeySizesForComparisonMode);

    // Calculate minimum, bin width, and number of bins for all combined results
    List<Long> allCombinedResults = new ArrayList<>();
    for (int modelIndex = startModelIndex; modelIndex < endModelIndex; modelIndex++) {
      allCombinedResults.addAll(resultsModels.get(modelIndex).getResults());
    }
    double min = BenchmarkingUtility.getMin(allCombinedResults) / 1E6;
    double binWidth = calculateFreedmanDiaconisBinWidth(keySizeIndex, allCombinedResults);
    int numBins = calculateNumberOfBins(keySizeIndex, allCombinedResults);

    // Initialize bin counts for each series
    Map<String, int[]> seriesBinCounts = new HashMap<>();

    // Iterate over each key and hash function combination
    for (int modelIndex = startModelIndex; modelIndex < endModelIndex; modelIndex++) {
      ResultsModel model = resultsModels.get(modelIndex);

      // Retrieve the hash function for the current combination
      String hashFunctionName = model.getHashFunctionName();
      String keyConfigString = model.getConfigString();
      String seriesName =
          modelIndex + ". " + keyConfigString + " - " + hashFunctionName;

      double[] values = model.getResults().stream().mapToDouble(ns -> ns / 1_000_000.0).toArray();

      // Populate bin counts
      seriesBinCounts.putIfAbsent(seriesName, new int[numBins]);
      for (double value : values) {
        int bin = (int) ((value - min) / binWidth);
        bin = Math.min(Math.max(bin, 0), numBins - 1);
        seriesBinCounts.get(seriesName)[bin]++;
      }
    }

    // Add the bin counts to the dataset
    for (Map.Entry<String, int[]> entry : seriesBinCounts.entrySet()) {
      String seriesName = entry.getKey();
      int[] binCounts = entry.getValue();
      addBinCountDataset(dataset, min, binWidth, numBins, seriesName, binCounts);
    }

    return dataset;
  }


  /**
   * Creates a dataset for a stacked histogram given a key size index.
   *
   * @param keyIndex Index of the key for which the dataset is prepared.
   * @return A CategoryDataset suitable for creating a stacked histogram.
   */
  private CategoryDataset createStackedHistogramDataset(int keyIndex) {
    // Create the dataset
    DefaultCategoryDataset dataset = new DefaultCategoryDataset();

    // Determine the combined range and bin width
    List<Long> combinedResults = results.subList(
        keyIndex * (this.totalTrials / totalKeys) * numRowsComparisonMode,
        (keyIndex * (this.totalTrials / totalKeys) * numRowsComparisonMode)
            + (this.totalTrials / totalKeys) * numRowsComparisonMode
    );
    double min = BenchmarkingUtility.getMin(combinedResults) / 1E6;
    double binWidth = calculateFreedmanDiaconisBinWidth(keyIndex, combinedResults);
    int numBins = calculateNumberOfBins(keyIndex, combinedResults);

    // Initialise bin counts for each series
    Map<String, int[]> seriesBinCounts = new HashMap<>();

    for (int i = keyIndex * (resultsModels.size() / numKeySizesForComparisonMode);
        i < keyIndex * (resultsModels.size() / numKeySizesForComparisonMode)
            + numRowsComparisonMode;
        i++) {

      ResultsModel model = resultsModels.get(i);
      String seriesName = i + ". " + comparisonModeRowHeaders.get(i % numRowsComparisonMode);
      seriesBinCounts.putIfAbsent(seriesName, new int[numBins]);

      double[] values = model.getResults().stream()
          .mapToDouble(ns -> ns / 1_000_000.0) // Convert to milliseconds
          .toArray();

      // Populate bin counts
      for (double value : values) {
        int bin = (int) ((value - min) / binWidth);
        bin = Math.min(Math.max(bin, 0), numBins - 1); // Clamp to valid range
        seriesBinCounts.get(seriesName)[bin]++;
      }
    }

    // Add the bin counts to the dataset
    for (Map.Entry<String, int[]> entry : seriesBinCounts.entrySet()) {
      String seriesName = entry.getKey();
      int[] binCounts = entry.getValue();
      addBinCountDataset(dataset, min, binWidth, numBins, seriesName, binCounts);
    }

    return dataset;
  }


  /**
   * Prepares a histogram dataset for a given key index for use in non-comparison mode.
   *
   * @param keyIndex The index of the key to prepare the dataset for.
   * @return A histogram dataset for the specified key.
   */
  private DefaultCategoryDataset prepareHistogramForKey(int keyIndex) {
    DefaultCategoryDataset dataset = new DefaultCategoryDataset();
    ResultsModel model = resultsModels.get(keyIndex);

    double min = model.getMinTimeData() / 1_000_000.0; // convert to milliseconds
    double binWidth = calculateFreedmanDiaconisBinWidth(keyIndex, model.getResults());
    int numBins = calculateNumberOfBins(keyIndex, model.getResults());
    String seriesName = "Key " + (keyIndex + 1);
    int[] binCounts = new int[numBins]; // Array to hold the count of values in each bin

    double[] values = model.getResults().stream()
        .mapToDouble(ns -> ns / 1_000_000.0) // Convert to milliseconds
        .toArray();

    // Populate bin counts
    for (double value : values) {
      int bin = (int) ((value - min) / binWidth);
      bin = Math.min(Math.max(bin, 0), numBins - 1); // Clamp to valid range
      binCounts[bin]++; // Increment the count for the bin
    }

    // Add the bin counts to the dataset
    addBinCountDataset(dataset, min, binWidth, numBins, seriesName, binCounts);

    return dataset;
  }

  /**
   * Adds data for bin counts to the given category dataset. This method is used for preparing
   * datasets for histogram graphs by populating it with frequency data for specific value ranges
   * (bins).
   *
   * @param dataset    The category dataset to which the bin counts will be added.
   * @param min        The minimum value in the range of data.
   * @param binWidth   The width of each bin (value range).
   * @param numBins    The total number of bins.
   * @param seriesName The name of the series to which this bin data belongs.
   * @param binCounts  An array of integers representing the count of values in each bin.
   */
  private void addBinCountDataset(DefaultCategoryDataset dataset, double min, double binWidth,
      int numBins, String seriesName, int[] binCounts) {
    for (int bin = 0; bin < numBins; bin++) {
      double lowerBound = min + (bin * binWidth);
      double upperBound = lowerBound + binWidth;
      // Format the bin range as a label
      String binLabel = String.format("%.1f-%.1f ms", lowerBound, upperBound);
      dataset.addValue(binCounts[bin], seriesName,
          binLabel); // Add the count of the bin to the dataset
    }
  }


  /**
   * Creates a stacked histogram chart using the provided dataset.
   *
   * @param dataset The dataset to create the histogram from.
   * @param title   The title of the histogram chart.
   * @return A JFreeChart object representing the stacked histogram chart.
   */
  private JFreeChart createStackedHistogramChart(CategoryDataset dataset, String title) {
    // Create the stacked bar chart with the dataset
    JFreeChart chart = ChartFactory.createStackedBarChart(
        title,
        "Category",
        "Frequency",
        dataset,
        PlotOrientation.VERTICAL,
        true,                  // include legend
        true,                  // tooltips
        false
    );
    //chart should be rendered as a stacked bar chart, where
    // each category contains stacked bars representing different bins of data
    CategoryPlot plot = chart.getCategoryPlot();
    StackedBarRenderer renderer = new StackedBarRenderer();
    plot.setRenderer(renderer);

    for (int i = 0; i < dataset.getRowCount(); i++) {
      // generate colors based on the hue, saturation, and brightness.
      // Each series is assigned a different hue value based on its index.
      Color color = Color.getHSBColor((float) i / dataset.getRowCount(), 0.85f, 0.85f);
      renderer.setSeriesPaint(i, color);
    }

    // Set the category label positions to avoid overlap
    CategoryAxis domainAxis = plot.getDomainAxis();
    domainAxis.setCategoryLabelPositions(CategoryLabelPositions.UP_45);

    return chart;
  }

  /**
   * Creates a histogram from the given category dataset.
   *
   * @param dataset The dataset from which the histogram is to be created.
   * @param title   The title for the histogram chart.
   * @return A JFreeChart object representing the histogram.
   */
  private JFreeChart createHistogramFromDataset(CategoryDataset dataset, String title) {
    JFreeChart chart = ChartFactory.createStackedBarChart(
        title,
        "Time (ms)",
        "Frequency",
        dataset,
        PlotOrientation.VERTICAL,
        false,
        true,
        false
    );
    CategoryPlot plot = chart.getCategoryPlot();
    StackedBarRenderer renderer = new StackedBarRenderer();
    plot.setRenderer(renderer);

    // Set the category label positions to avoid overlap
    CategoryAxis domainAxis = plot.getDomainAxis();
    domainAxis.setCategoryLabelPositions(CategoryLabelPositions.UP_45);

    return chart;


  }

  /**
   * Creates a BoxAndWhiskerItem from the provided ResultsModel.
   *
   * @param model The model containing statistical data.
   * @return A BoxAndWhiskerItem representing the statistical data.
   */
  private BoxAndWhiskerItem createBoxAndWhiskerItem(ResultsModel model) {
    double mean = model.getMeanData();
    double median = model.getMedianData();
    double q1 = model.getPercentile25Data();
    double q3 = model.getPercentile75Data();
    double min = model.getMinTimeData();
    double max = model.getMaxTimeData();

    return new BoxAndWhiskerItem(
        mean,
        median,
        q1,
        q3,
        min,
        max,
        null, // Min outlier
        null,     // Max outlier
        null     // Outlier list
    );
  }

  /**
   * Prepares a dataset for the box plot for a specific key.
   *
   * @param keyIndex Index of the key for which the dataset is prepared.
   * @return A dataset ready for generating a box plot.
   */
  private DefaultBoxAndWhiskerCategoryDataset prepareBoxPlotDatasetForKey(int keyIndex) {
    DefaultBoxAndWhiskerCategoryDataset dataset = new DefaultBoxAndWhiskerCategoryDataset();
    ResultsModel model = resultsModels.get(keyIndex);

    dataset.add(createBoxAndWhiskerItem(model), "Key " + keyIndex + 1, "");
    return dataset;
  }

  /**
   * Prepares a dataset for the box plot in comparison mode (in the context of signature
   * operations), collecting statistics from multiple results models.
   *
   * @param keySizeIndex Index of the key size for which the dataset is prepared.
   * @return A dataset ready for generating a box plot.
   */
  private DefaultBoxAndWhiskerCategoryDataset prepareBoxPlotDatasetForComparisonModeSignatures(
      int keySizeIndex) {
    DefaultBoxAndWhiskerCategoryDataset dataset = new DefaultBoxAndWhiskerCategoryDataset();

    int startModelIndex = keySizeIndex * (resultsModels.size() / numKeySizesForComparisonMode);
    int endModelIndex = (keySizeIndex + 1) * (resultsModels.size() / numKeySizesForComparisonMode);

    for (int modelIndex = startModelIndex; modelIndex < endModelIndex; modelIndex++) {
      ResultsModel model = resultsModels.get(modelIndex);

      // Retrieve the hash function for the current combination
      String hashFunctionName = model.getHashFunctionName();
      String keyConfigString = model.getConfigString();
      String seriesName =
          modelIndex + ". " + keyConfigString + " - " + hashFunctionName;

      dataset.add(createBoxAndWhiskerItem(model), seriesName, seriesName);

    }

    return dataset;
  }

  /**
   * Prepares a dataset for a box plot in comparison mode. This method aggregates the statistical
   * data from multiple ResultsModel instances to create a dataset suitable for generating box
   * plots. Each entry in the dataset represents the distribution of benchmarking results for a
   * particular parameter type or key configuration in the comparison mode.
   *
   * @param keyIndex The index of the key size for which the dataset is prepared.
   * @return A box-and-whisker dataset representing the aggregated results for the specified key
   * size.
   */
  private DefaultBoxAndWhiskerCategoryDataset prepareBoxPlotDatasetForComparisonMode(
      int keyIndex) {
    DefaultBoxAndWhiskerCategoryDataset dataset = new DefaultBoxAndWhiskerCategoryDataset();

    for (int i = keyIndex * (resultsModels.size() / numKeySizesForComparisonMode);
        i < keyIndex * (resultsModels.size() / numKeySizesForComparisonMode)
            + numRowsComparisonMode;
        i++) {

      ResultsModel model = resultsModels.get(i);
      String seriesName = i + ". " +
          comparisonModeRowHeaders.get(i % numRowsComparisonMode);

      // Extract necessary statistics and add to dataset
      dataset.add(createBoxAndWhiskerItem(model), seriesName, seriesName);
    }
    return dataset;
  }


  /**
   * Prepares datasets for the line chart displaying mean times for signature operations in
   * comparison mode.
   *
   * @param keySizeIndex Index of the key size for which the datasets are prepared.
   * @return A pair containing two datasets: one for the mean times and one for the error intervals.
   */
  private Pair<XYSeriesCollection, YIntervalSeriesCollection> prepareLineChartMeanDatasetForComparisonModeSignatures(
      int keySizeIndex) {
    XYSeriesCollection meanDataset = new XYSeriesCollection();
    YIntervalSeriesCollection errorDataset = new YIntervalSeriesCollection();

    XYSeries meanSeries = new XYSeries("Mean Times");
    YIntervalSeries errorSeries = new YIntervalSeries("Error Bars");

    int startModelIndex = keySizeIndex * (resultsModels.size() / numKeySizesForComparisonMode);
    int endModelIndex = (keySizeIndex + 1) * (resultsModels.size() / numKeySizesForComparisonMode);

    // Iterate over each key within the key size range
    for (int modelIndex = startModelIndex; modelIndex < endModelIndex; modelIndex++) {
      ResultsModel model = resultsModels.get(modelIndex);

      double mean = model.getMeanData();
      double stdDev = model.getStdDeviationData();

      // X-value for the series should be based on the group index
      int xValue = (modelIndex % (resultsModels.size() / numKeySizesForComparisonMode));

      meanSeries.add(xValue, mean);
      errorSeries.add(xValue, mean, mean - stdDev, mean + stdDev);
    }

    meanDataset.addSeries(meanSeries);
    errorDataset.addSeries(errorSeries);

    return new Pair<>(meanDataset, errorDataset);
  }


  /**
   * Prepares datasets for the mean times line chart in comparison mode.
   *
   * @param keyIndex Index of the key for which the datasets are prepared.
   * @return A pair containing two datasets: one for the mean times and one for the error intervals.
   */
  private Pair<XYSeriesCollection, YIntervalSeriesCollection> prepareLineChartMeanDatasetForComparisonMode(
      int keyIndex) {
    XYSeriesCollection meanDataset = new XYSeriesCollection();
    YIntervalSeriesCollection errorDataset = new YIntervalSeriesCollection();

    XYSeries meanSeries = new XYSeries("Mean Times");
    YIntervalSeries errorSeries = new YIntervalSeries("Error Bars (Standard Deviation)");

    for (int i = keyIndex * (resultsModels.size() / numKeySizesForComparisonMode);
        i < keyIndex * (resultsModels.size() / numKeySizesForComparisonMode)
            + numRowsComparisonMode;
        i++) {

      ResultsModel model = resultsModels.get(i);
      double mean = model.getMeanData();
      double stdDev = model.getStdDeviationData();

      int xValue = i % numRowsComparisonMode;

      meanSeries.add(xValue, mean);
      errorSeries.add(xValue, mean, mean - stdDev, mean + stdDev);
    }

    meanDataset.addSeries(meanSeries);
    errorDataset.addSeries(errorSeries);
    return new Pair<>(meanDataset, errorDataset);
  }


  /**
   * Configures the renderers for the line chart displaying mean times.
   *
   * @param plot The plot to which the renderers will be applied.
   */
  private void configureLineChartMeanRenderers(XYPlot plot) {
    // Mean dataset renderer
    XYLineAndShapeRenderer meanRenderer = new XYLineAndShapeRenderer();
    meanRenderer.setSeriesLinesVisible(0, true);
    meanRenderer.setSeriesShapesVisible(0, true);

    plot.setRenderer(0, meanRenderer);

    // Error dataset renderer
    XYErrorRenderer errorRenderer = new XYErrorRenderer();
    errorRenderer.setSeriesLinesVisible(0, true);
    errorRenderer.setSeriesShapesVisible(0, false); // No shapes for error bars
    errorRenderer.setDrawYError(true); // Enable vertical error bars
    errorRenderer.setDrawXError(false); // Disable horizontal error bars
    plot.setRenderer(1, errorRenderer);
  }

  /**
   * Creates a line chart for displaying mean times in comparison mode. This chart visually
   * represents the average performance across different parameter sets or key configurations. It is
   * particularly useful in comparison mode where multiple configurations are benchmarked against
   * each other.
   *
   * @param meanDataset  A dataset containing the mean times for each configuration.
   * @param errorDataset A dataset containing error intervals for each mean time.
   * @param title        The title of the line chart.
   * @return A JFreeChart object representing the line chart with mean times.
   */
  private JFreeChart createLineChartMeanForComparisonMode(XYSeriesCollection meanDataset,
      YIntervalSeriesCollection errorDataset, String title) {

    JFreeChart lineChart = ChartFactory.createXYLineChart(
        title,
        "Parameter Type",
        "Mean Time (ms)",
        meanDataset,
        PlotOrientation.VERTICAL,
        true,
        true,
        false
    );

    XYPlot plot = lineChart.getXYPlot();
    plot.setDataset(1, errorDataset); // Set error dataset as secondary dataset
    configureLineChartMeanRenderers(plot);

    String[] paramTypeLabels = new String[numRowsComparisonMode];
    for (int i = 0; i < numRowsComparisonMode; i++) {
      paramTypeLabels[i] = i + ". " + comparisonModeRowHeaders.get(i);
    }

    SymbolAxis xAxis = new SymbolAxis("Parameter Type", paramTypeLabels);
    xAxis.setTickLabelsVisible(true);
    xAxis.setTickLabelFont(new Font("SansSerif", Font.PLAIN, 7));
    plot.setDomainAxis(xAxis);

    return lineChart;
  }


  /**
   * Creates a line chart for mean times, specific to signature operations in comparison mode.
   *
   * @param meanDataset  The dataset for mean times.
   * @param errorDataset The dataset for error intervals.
   * @param title        The title of the chart.
   * @param keySizeIndex Index of the key size used in the chart.
   * @return A JFreeChart object representing the line chart.
   */
  private JFreeChart createLineChartMeanForComparisonModeSignatures(XYSeriesCollection meanDataset,
      YIntervalSeriesCollection errorDataset, String title, int keySizeIndex) {

    JFreeChart lineChart = ChartFactory.createXYLineChart(
        title,
        "Parameter Type",
        "Mean Time (ms)",
        meanDataset,
        PlotOrientation.VERTICAL,
        true,
        true,
        false
    );

    XYPlot plot = lineChart.getXYPlot();
    plot.setDataset(1, errorDataset); // Set error dataset as secondary dataset
    configureLineChartMeanRenderers(plot);

    int modelsPerKeySize = resultsModels.size() / numKeySizesForComparisonMode;
    String[] paramTypeLabels = new String[resultsModels.size() / numKeySizesForComparisonMode];
    for (int i = 0; i < modelsPerKeySize; i++) {
      ResultsModel model = resultsModels.get(i);
      String hashFunctionName = model.getHashFunctionName();
      String keyConfigString = model.getConfigString();
      paramTypeLabels[i] = i + ". " + keyConfigString + " - " + hashFunctionName;
    }

    SymbolAxis xAxis = new SymbolAxis("Parameter Type", paramTypeLabels);
    xAxis.setTickLabelsVisible(true);
    xAxis.setTickLabelFont(new Font("SansSerif", Font.PLAIN, 7));

    plot.setDomainAxis(xAxis);

    return lineChart;
  }


  /**
   * Displays a histogram for a specific key size which contains results for multiple keys
   * (comparison mode).
   *
   * @param keyIndex Index of the key size for which the histogram is displayed.
   * @return A ChartViewer containing the stacked histogram.
   */
  public ChartViewer displayStackedHistogram(int keyIndex) {
    CategoryDataset dataset;
    if (isSignatureOperationResults) {
      dataset = createStackedHistogramDatasetSignatures(keyIndex);
    } else {
      dataset = createStackedHistogramDataset(keyIndex);
    }
    int startModelIndex = keyIndex * (resultsModels.size() / numKeySizesForComparisonMode);
    JFreeChart chart = createStackedHistogramChart(dataset,
        "Stacked Histogram for " + "Key Size " + (keyIndex + 1) + " (" + keyLengths.get(
            startModelIndex % keyLengths.size()) + "bit)");
    return new ChartViewer(chart);
  }

  /**
   * Displays a histogram for a specific key.
   *
   * @param keyIndex Index of the key for which the histogram is displayed.
   * @return A ChartViewer containing the histogram.
   */
  public ChartViewer displayHistogramForKey(int keyIndex) {
    CategoryDataset dataset = prepareHistogramForKey(keyIndex);
    JFreeChart chart = createHistogramFromDataset(dataset,
        "Histogram for " + "Key " + (keyIndex + 1) + " (" + keyLengths.get(keyIndex) + "bit)");
    return new ChartViewer(chart);
  }

  /**
   * Displays a box plot using the provided dataset.
   *
   * @param dataset           The dataset to be used for the box plot.
   * @param title             The title of the chart.
   * @param categoryAxisLabel The label for the category axis.
   * @return A ChartViewer containing the box plot.
   */
  private ChartViewer displayBoxPlot(DefaultBoxAndWhiskerCategoryDataset dataset, String title,
      String categoryAxisLabel) {
    JFreeChart boxplot = ChartFactory.createBoxAndWhiskerChart(
        title, categoryAxisLabel, "Time (ms)", dataset, true);

    return new ChartViewer(boxplot);
  }

  /**
   * Prepares and displays a box plot for a specific key.
   *
   * @param keyIndex Index of the key for which the box plot is prepared.
   * @return A ChartViewer containing the box plot.
   */
  private ChartViewer displayBoxPlotForKey(int keyIndex) {
    DefaultBoxAndWhiskerCategoryDataset dataset = prepareBoxPlotDatasetForKey(keyIndex);

    // Create the chart
    JFreeChart chart = ChartFactory.createBoxAndWhiskerChart(
        "Box plot for Key " + (keyIndex + 1) + " (" + keyLengths.get(keyIndex) + "bit)",    // Title
        "Key " + (keyIndex + 1) + " (" + keyLengths.get(keyIndex) + "bit)",
        // X-axis label
        "Time (ms)",               // Y-axis label
        dataset,               // Dataset
        false                  // Not include legend
    );

    CategoryPlot plot = (CategoryPlot) chart.getPlot();
    plot.setDomainGridlinesVisible(true);
    plot.setRangePannable(true);

    NumberAxis rangeAxis = (NumberAxis) plot.getRangeAxis();
    rangeAxis.setStandardTickUnits(NumberAxis.createIntegerTickUnits());
    ChartViewer viewer = new ChartViewer(chart);
    return viewer;
  }


  /**
   * Displays a box plot for the benchmarking results in comparison mode. This method generates a
   * box-and-whisker plot that visually represents the distribution of results (like median,
   * quartiles, etc.) for each parameter set or key configuration. It's used to compare the
   * performance metrics in a concise and informative way.
   *
   * @param keyIndex The index of the key size for which the box plot is displayed.
   * @return A ChartViewer containing the generated box plot.
   */
  private ChartViewer displayBoxPlotForComparisonMode(int keyIndex) {
    DefaultBoxAndWhiskerCategoryDataset dataset;
    if (isSignatureOperationResults) {
      dataset = prepareBoxPlotDatasetForComparisonModeSignatures(keyIndex);
    } else {
      dataset = prepareBoxPlotDatasetForComparisonMode(keyIndex);
    }
    int startModelIndex = keyIndex * (resultsModels.size() / numKeySizesForComparisonMode);
    return displayBoxPlot(dataset,
        "Box Plot for " + "Key Size " + (keyIndex + 1) + " (" + keyLengths.get(
            startModelIndex % keyLengths.size()) + "bit)",
        "Parameter Type");
  }


  /**
   * Displays a line graph for mean times in comparison mode.
   *
   * @param keyIndex Index of the key size for which the line graph is displayed.
   * @return A ChartViewer containing the line graph.
   */
  private ChartViewer displayLineGraphMeanForComparisonMode(int keyIndex) {
    Pair<XYSeriesCollection, YIntervalSeriesCollection> datasets;
    int keyLength = 0;
    if (isSignatureOperationResults) {
      datasets = prepareLineChartMeanDatasetForComparisonModeSignatures(keyIndex);
      int startModelIndex = keyIndex * (resultsModels.size() / numKeySizesForComparisonMode);
      keyLength = resultsModels.get(startModelIndex).getKeyLength();
    } else {
      datasets = prepareLineChartMeanDatasetForComparisonMode(keyIndex);
    }

    XYSeriesCollection meanDataset = datasets.getKey();
    YIntervalSeriesCollection errorDataset = datasets.getValue();
    return isSignatureOperationResults ? new ChartViewer(
        createLineChartMeanForComparisonModeSignatures(meanDataset, errorDataset,
            "Line Graph (Mean) for " + "Key Size " + (keyIndex + 1) + " (" + keyLength + "bit)",
            keyIndex))
        : new ChartViewer(
            createLineChartMeanForComparisonMode(meanDataset, errorDataset,
                "Line Graph (Mean) for " + "Key Size " + (keyIndex + 1) + " (" + keyLengths.get(
                    keyIndex * (resultsModels.size() / numKeySizesForComparisonMode)) + "bit)"));

  }


}
