package uk.msci.project.rsa;

import java.awt.Color;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
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
import org.jfree.chart.renderer.category.BoxAndWhiskerRenderer;
import org.jfree.chart.renderer.category.StackedBarRenderer;
import org.jfree.chart.renderer.xy.XYErrorRenderer;
import org.jfree.chart.renderer.xy.XYLineAndShapeRenderer;
import org.jfree.data.category.CategoryDataset;
import org.jfree.data.category.DefaultCategoryDataset;
import org.jfree.data.statistics.BoxAndWhiskerItem;
import org.jfree.data.statistics.DefaultBoxAndWhiskerCategoryDataset;
import org.jfree.data.statistics.HistogramDataset;
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
   * The number of trials conducted per key in the benchmarking process.
   */
  private int trialsPerKey;

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
   * Header text for the first row in comparison mode.
   */
  private static final String FIRST_ROW_COMPARISON_MODE = "Standard Parameters (2 Primes):";

  /**
   * Header text for the second row in comparison mode.
   */
  private static final String SECOND_ROW_COMPARISON_MODE = "Standard Parameters (3 Primes):";

  /**
   * Header text for the third row in comparison mode.
   */
  private static final String THIRD_ROW_COMPARISON_MODE = "Provable Parameters (2 Primes):";

  /**
   * Header text for the fourth row in comparison mode.
   */
  private static final String FOURTH_ROW_COMPARISON_MODE = "Provable Parameters (3 Primes):";

  /**
   * The number of rows used in comparison mode.
   */
  private static final int NUM_ROWS_COMPARISON_MODE = 4;

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
      this.trialsPerKey = totalTrials / totalKeys;
      this.keyIndex = 0;
      splitResultsByKeys();
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
          precomputeGraphs();
          resultsView.setLineGraphButtonMeanVisibility(false);
        });
  }

  /**
   * Displays the results view in either standard or comparison mode. In comparison mode, it
   * configures the view to compare results across multiple key sizes and parameter sets (provably
   * secure vs standard).
   *
   * @param primaryStage                 The primary stage for the application.
   * @param results                      List of benchmarking results to be displayed.
   * @param keyLengths                   List of key lengths used in the benchmarking process.
   * @param isComparisonMode             Flag indicating if comparison mode is active.
   * @param numKeySizesForComparisonMode Number of key sizes to be compared in comparison mode.
   */
  public void showResultsView(Stage primaryStage, List<Long> results, List<Integer> keyLengths,
      boolean isComparisonMode, int numKeySizesForComparisonMode) {
    if (!isComparisonMode) {
      showResultsView(primaryStage, results, keyLengths);
      return;
    }
    this.numKeySizesForComparisonMode = numKeySizesForComparisonMode;
    loadResultsView(keyLengths, results, this::setupComparisonModeGraphObservers,
        () -> {
          initialiseKeySwitchButtonsComparisonMode();
          precomputeGraphsComparisonMode();
          resultsView.removeValueColumn();
          resultsView.addValueColumns(createComparisonModeColumnHeaders());
          resultsView.setNameColumnText("Parameter Type");
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

      String lineChartKey = "LineChartAllTimes_" + keyIndex;
      ChartViewer lineChartViewer = displayLineChartAllTimes(keyIndex,
          "Line Graph (All Trials) for " + "Key " + (keyIndex + 1) + " (" + keyLengths.get(
              keyIndex) + "bit)");
      precomputedGraphs.put(lineChartKey, lineChartViewer);

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

      String lineChartAllTimesKey = "LineChartAllTimes_" + keySizeIndex;
      ChartViewer lineChartAllTimesViewer = displayLineChartAllTimesComparisonMode(keySizeIndex,
          "Line Graph (All Trials) for " + "Key Size " + (keySizeIndex + 1) + " (" + keyLengths.get(
              keySizeIndex * (resultsModels.size() / numKeySizesForComparisonMode)) + "bit)");

      precomputedGraphs.put(lineChartAllTimesKey, lineChartAllTimesViewer);

      String lineChartMeanKey = "LineChartMeanTimes_" + keySizeIndex;
      ChartViewer lineChartMeanViewer = displayLineGraphMeanForComparisonMode(keySizeIndex);
      precomputedGraphs.put(lineChartMeanKey, lineChartMeanViewer);

      String boxPlotKey = "BoxPlot_" + keySizeIndex;
      ChartViewer boxPlotViewer = displayBoxPlotForComparisonMode(keySizeIndex);
      precomputedGraphs.put(boxPlotKey, boxPlotViewer);

    }
  }


  /**
   * Creates headers for the columns in the comparison mode table view. These headers correspond to
   * different statistics that will be compared.
   *
   * @return A list of ResultsTableColumn objects initialized with header titles.
   */
  private List<ResultsTableColumn> createComparisonModeColumnHeaders() {
    List<ResultsTableColumn> resultsTableColumnList = new ArrayList<>();
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
   * Splits the results into groups based on keys and creates a ResultsModel for each group.
   */
  private void splitResultsByKeys() {
    for (int keyIndex = 0; keyIndex < totalKeys; keyIndex++) {
      List<Long> keySpecificResults = extractKeySpecificResults(keyIndex);
      ResultsModel resultsModel = new ResultsModel(keySpecificResults);
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
    resultsView.setResultsLabel(currentContext.getResultsLabel());

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
    resultsView.addLineGraphButtonAllTimesObserver(new LineGraphButtonAllTimesObserver());
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
   * Retrieves the appropriate header text for a given row in comparison mode. The header text
   * corresponds to the specific parameter set and prime configuration.
   *
   * @param row The row index for which the header text is required.
   * @return A string representing the header text for the specified row.
   * @throws IllegalArgumentException If the row index does not correspond to a valid row.
   */
  public String getComparisonModeRowHeader(int row) {
    return switch (row) {
      case 0 -> FIRST_ROW_COMPARISON_MODE;
      case 1 -> SECOND_ROW_COMPARISON_MODE;
      case 2 -> THIRD_ROW_COMPARISON_MODE;
      case 3 -> FOURTH_ROW_COMPARISON_MODE;
      default -> {
        throw new IllegalArgumentException("Invalid row: " + row);
      }
    };
  }


  /**
   * Prepares the data for display in comparison mode by aggregating the statistics for each
   * parameter set into a list of StatisticData objects.
   *
   * @param keyIndex The index of the key for which the comparison data is being prepared.
   * @return A list of StatisticData objects, each representing the aggregated statistics for a
   * parameter set.
   */
  private List<StatisticData> prepareComparisonData(int keyIndex) {
    List<StatisticData> comparisonData = new ArrayList<>();

    // Collecting data from each ResultsModel
    for (int i = keyIndex * (resultsModels.size() / numKeySizesForComparisonMode);
        i < keyIndex * (resultsModels.size() / numKeySizesForComparisonMode)
            + NUM_ROWS_COMPARISON_MODE; i++) {
      List<String> parameterRow = new ArrayList<>();
      parameterRow.add(String.valueOf(resultsModels.get(i).getNumTrials()));
      parameterRow.add(String.format("%.5f ms", resultsModels.get(i).getOverallData()));
      parameterRow.add(String.format("%.5f ms", resultsModels.get(i).getMeanData()));
      parameterRow.add(
          String.format("%.5f ms", resultsModels.get(i).getStdDeviationData()));
      parameterRow.add(String.format("%.5f ms²", resultsModels.get(i).getVarianceData()));
      double[] confidenceInterval = resultsModels.get(i).getConfidenceInterval();
      parameterRow.add(
          String.format("95%% with bounds [%.5f, %.5f]", confidenceInterval[0],
              confidenceInterval[1])
      );
      parameterRow.add(
          String.format("%.5f ms", resultsModels.get(i).getPercentile25Data()));
      parameterRow.add(String.format("%.5f ms", resultsModels.get(i).getMedianData()));
      parameterRow.add(
          String.format("%.5f ms", resultsModels.get(i).getPercentile75Data()));
      parameterRow.add(String.format("%.5f ms", resultsModels.get(i).getRangeData()));
      parameterRow.add(String.format("%.5f ms", resultsModels.get(i).getMinTimeData()));
      parameterRow.add(String.format("%.5f ms", resultsModels.get(i).getMaxTimeData()));
      comparisonData.add(
          new StatisticData(getComparisonModeRowHeader(i % NUM_ROWS_COMPARISON_MODE),
              parameterRow));
    }

    return comparisonData;
  }


  /**
   * Extracts results specific to a key from the overall benchmarking results.
   *
   * @param keyIndex The index of the key for which to extract results.
   * @return A list of long values representing the results for the specified key.
   */
  private List<Long> extractKeySpecificResults(int keyIndex) {
    int startIndex = keyIndex * trialsPerKey;
    int endIndex = startIndex + trialsPerKey;
    return results.subList(startIndex, endIndex);
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
          "Key Size " + (keySizeIndex + 1) + " (" + keyLengths.get(
              keySizeIndex * (resultsModels.size() / numKeySizesForComparisonMode)) + "bit)");

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
   * Observer for displaying a line graph view with all individual times from the results for the
   * current key/key size.
   */
  class LineGraphButtonAllTimesObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
      String lineChartAllTimesKey = "LineChartAllTimes_" + keyIndex;
      ChartViewer viewer = precomputedGraphs.get(lineChartAllTimesKey);
      resultsView.updateGraphArea(viewer);
      lastSelectedGraphButton = resultsView.getLineGraphButtonAllTimes();
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
              currentContext.getResultsLabel() + "_" + keyLengths.get(keyIndex) + "bit.csv");
        } else {
          resultsView.exportComparisonTableResultsToCSV(
              currentContext.getResultsLabel() + "_comparisonMode.csv");
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
        keyIndex * trialsPerKey * NUM_ROWS_COMPARISON_MODE,
        (keyIndex * trialsPerKey * NUM_ROWS_COMPARISON_MODE)
            + trialsPerKey * NUM_ROWS_COMPARISON_MODE
    );
    double min = BenchmarkingUtility.getMin(combinedResults) / 1E6;
    double binWidth = calculateFreedmanDiaconisBinWidth(keyIndex, combinedResults);
    int numBins = calculateNumberOfBins(keyIndex, combinedResults);

    // Initialise bin counts for each series
    Map<String, int[]> seriesBinCounts = new HashMap<>();

    for (int i = keyIndex * (resultsModels.size() / numKeySizesForComparisonMode);
        i < keyIndex * (resultsModels.size() / numKeySizesForComparisonMode)
            + NUM_ROWS_COMPARISON_MODE;
        i++) {

      ResultsModel model = resultsModels.get(i);
      String seriesName = getComparisonModeRowHeader(i % NUM_ROWS_COMPARISON_MODE);
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
      for (int bin = 0; bin < numBins; bin++) {
        // Calculate the lower and upper bounds for the current bin
        double lowerBound = min + (bin * binWidth);
        double upperBound = lowerBound + binWidth;
        // Format the bin range as a label
        String binLabel = String.format("%.1f-%.1f ms", lowerBound, upperBound);
        dataset.addValue(binCounts[bin], seriesName, binLabel);
      }
    }

    return dataset;
  }

  /**
   * Prepares a histogram dataset for a given key index for use in non-comparison mode.
   *
   * @param keyIndex The index of the key to prepare the dataset for.
   * @return A histogram dataset for the specified key.
   */
  private HistogramDataset prepareHistogramDatasetForKey(int keyIndex) {
    HistogramDataset dataset = new HistogramDataset();
    ResultsModel model = resultsModels.get(keyIndex);

    double q1 = model.getPercentile25Data();
    double q3 = model.getPercentile75Data();
    double binWidth = 2 * ((q3 - q1) / 1E6) * Math.pow(trialsPerKey, -1 / 3.0);

    double min = model.getMinTimeData() / 1E6;
    double max = model.getMaxTimeData() / 1E6;
    int numBins = (int) Math.ceil((max - min) / binWidth);

    double[] values = model.getResults().stream()
        .mapToDouble(ns -> ns / 1E6) // Convert to milliseconds
        .toArray();

    dataset.addSeries("Key " + keyIndex, values, numBins);
    return dataset;
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
  private JFreeChart createHistogramFromDataset(HistogramDataset dataset, String title) {
    return ChartFactory.createHistogram(
        title,
        "Time (ms)",
        "Frequency",
        dataset,
        PlotOrientation.VERTICAL,
        false,
        true,
        false
    );


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
   * Prepares a dataset for the box plot in comparison mode, collecting statistics from multiple
   * results models.
   *
   * @param keyIndex Index of the key for which the dataset is prepared.
   * @return A dataset ready for generating a box plot.
   */
  private DefaultBoxAndWhiskerCategoryDataset prepareBoxPlotDatasetForComparisonMode(
      int keyIndex) {
    DefaultBoxAndWhiskerCategoryDataset dataset = new DefaultBoxAndWhiskerCategoryDataset();

    for (int i = keyIndex * (resultsModels.size() / numKeySizesForComparisonMode);
        i < keyIndex * (resultsModels.size() / numKeySizesForComparisonMode)
            + NUM_ROWS_COMPARISON_MODE;
        i++) {

      ResultsModel model = resultsModels.get(i);
      String seriesName =
          getComparisonModeRowHeader(i % NUM_ROWS_COMPARISON_MODE);

      // Extract necessary statistics and add to dataset
      dataset.add(createBoxAndWhiskerItem(model), seriesName, seriesName);
    }
    return dataset;
  }

  /**
   * Prepares a line chart dataset for a specific key using all time data.
   *
   * @param keyIndex Index of the key for which the dataset is prepared.
   * @return An XYSeriesCollection for the line chart.
   */
  private XYSeriesCollection prepareLineChartAllTimesDataset(int keyIndex) {
    XYSeriesCollection dataset = new XYSeriesCollection();

    ResultsModel model = resultsModels.get(keyIndex);
    String seriesName = "Key " + keyIndex + 1;
    XYSeries series = new XYSeries(seriesName);

    for (int trial = 0; trial < model.getResults().size(); trial++) {
      double time = model.getResults().get(trial) / 1_000_000.0; // Convert to milliseconds
      series.add(trial, time);
    }

    dataset.addSeries(series);

    return dataset;
  }

  /**
   * Prepares a line chart dataset for comparison mode using all time data.
   *
   * @param keyIndex Index of the key for which the dataset is prepared.
   * @return An XYSeriesCollection for the line chart.
   */
  private XYSeriesCollection prepareLineChartAllTimesDatasetComparisonMode(int keyIndex) {
    XYSeriesCollection dataset = new XYSeriesCollection();

    for (int i = keyIndex * (resultsModels.size() / numKeySizesForComparisonMode);
        i < keyIndex * (resultsModels.size() / numKeySizesForComparisonMode)
            + NUM_ROWS_COMPARISON_MODE;
        i++) {

      ResultsModel model = resultsModels.get(i);
      String seriesName =
          getComparisonModeRowHeader(i % NUM_ROWS_COMPARISON_MODE);
      XYSeries series = new XYSeries(seriesName);

      // Assuming each trial is a point on the x-axis
      for (int trial = 0; trial < model.getResults().size(); trial++) {
        double time = model.getResults().get(trial) / 1_000_000.0; // Convert to milliseconds
        series.add(trial, time);
      }

      dataset.addSeries(series);
    }

    return dataset;
  }

  /**
   * Creates a line chart from the given dataset.
   *
   * @param dataset The dataset for the line chart.
   * @param title   The title for the chart.
   * @return A JFreeChart object representing the line chart.
   */
  private JFreeChart createLineChartAllTimes(XYSeriesCollection dataset, String title) {
    JFreeChart lineChart = ChartFactory.createXYLineChart(
        title,
        "Trial",
        "Time (ms)",
        dataset,
        PlotOrientation.VERTICAL,
        false,
        true,
        false
    );

    XYPlot plot = lineChart.getXYPlot();
    XYLineAndShapeRenderer renderer = new XYLineAndShapeRenderer();
    plot.setRenderer(renderer);

    return lineChart;
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
            + NUM_ROWS_COMPARISON_MODE;
        i++) {

      ResultsModel model = resultsModels.get(i);
      double mean = model.getMeanData();
      double stdDev = model.getStdDeviationData();

      int xValue = i % NUM_ROWS_COMPARISON_MODE;

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
   * Creates a line chart for mean times with error bars for standard deviation.
   *
   * @param meanDataset  The dataset containing the mean times.
   * @param errorDataset The dataset containing the error bars.
   * @param title        The title for the chart.
   * @return A JFreeChart object representing the line chart.
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

    String[] paramTypeLabels = new String[NUM_ROWS_COMPARISON_MODE];
    for (int i = 0; i < NUM_ROWS_COMPARISON_MODE; i++) {
      paramTypeLabels[i] = getComparisonModeRowHeader(i);
    }

    SymbolAxis xAxis = new SymbolAxis("Parameter Type", paramTypeLabels);
    xAxis.setTickLabelsVisible(true);
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
    CategoryDataset dataset = createStackedHistogramDataset(keyIndex);
    JFreeChart chart = createStackedHistogramChart(dataset,
        "Stacked Histogram for " + "Key Size " + (keyIndex + 1) + " (" + keyLengths.get(
            keyIndex * (resultsModels.size() / numKeySizesForComparisonMode)) + "bit)");
    return new ChartViewer(chart);
  }

  /**
   * Displays a histogram for a specific key.
   *
   * @param keyIndex Index of the key for which the histogram is displayed.
   * @return A ChartViewer containing the histogram.
   */
  public ChartViewer displayHistogramForKey(int keyIndex) {
    HistogramDataset dataset = prepareHistogramDatasetForKey(keyIndex);

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
   * Prepares and displays a box plot for comparison mode.
   *
   * @param keyIndex Index of the key for which the box plot is prepared.
   * @return A ChartViewer containing the box plot.
   */
  private ChartViewer displayBoxPlotForComparisonMode(int keyIndex) {
    DefaultBoxAndWhiskerCategoryDataset dataset = prepareBoxPlotDatasetForComparisonMode(
        keyIndex);
    return displayBoxPlot(dataset,
        "Box Plot for " + "Key Size " + (keyIndex + 1) + " (" + keyLengths.get(
            keyIndex * (resultsModels.size() / numKeySizesForComparisonMode)) + "bit)",
        "Parameter Type");
  }

  /**
   * Displays a line chart for all times for a specific key.
   *
   * @param keyIndex Index of the key for which the line chart is displayed.
   * @param title    The title for the chart.
   * @return A ChartViewer containing the line chart.
   */
  private ChartViewer displayLineChartAllTimes(int keyIndex, String title) {
    XYSeriesCollection dataset = prepareLineChartAllTimesDataset(keyIndex);
    JFreeChart chart = createLineChartAllTimes(dataset, title);
    return new ChartViewer(chart);
  }

  /**
   * Displays a line chart for all times in comparison mode.
   *
   * @param keyIndex Index of the key for which the line chart is displayed.
   * @param title    The title for the chart.
   * @return A ChartViewer containing the line chart.
   */
  private ChartViewer displayLineChartAllTimesComparisonMode(int keyIndex, String title) {
    XYSeriesCollection dataset = prepareLineChartAllTimesDatasetComparisonMode(keyIndex);
    JFreeChart chart = createLineChartAllTimes(dataset, title);
    return new ChartViewer(chart);
  }

  /**
   * Prepares and displays a line chart for mean times in comparison mode.
   *
   * @param keyIndex Index of the key for which the line chart is displayed.
   * @return A ChartViewer containing the line chart.
   */
  private ChartViewer displayLineGraphMeanForComparisonMode(int keyIndex) {
    Pair<XYSeriesCollection, YIntervalSeriesCollection> datasets = prepareLineChartMeanDatasetForComparisonMode(
        keyIndex);
    XYSeriesCollection meanDataset = datasets.getKey();
    YIntervalSeriesCollection errorDataset = datasets.getValue();
    return new ChartViewer(
        createLineChartMeanForComparisonMode(meanDataset, errorDataset,
            "Line Graph (Mean) for " + "Key Size " + (keyIndex + 1) + " (" + keyLengths.get(
                keyIndex * (resultsModels.size() / numKeySizesForComparisonMode)) + "bit)"));

  }


}
