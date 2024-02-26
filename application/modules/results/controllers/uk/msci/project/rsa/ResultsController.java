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
   * Constructs a new ResultsController with a reference to the MainController.
   *
   * @param mainController The main controller of the application.
   */
  public ResultsController(MainController mainController) {
    this.mainController = mainController;

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
   * Displays the results view and initialises the results model with the provided benchmarking
   * results. This method prepares the results view by configuring it based on the current
   * benchmarking context, including the display of statistical results for each key. It also sets
   * up key-specific navigation within the view, allowing the user to switch between results for
   * different keys.
   *
   * @param primaryStage The primary stage on which the results view is to be set. This is the main
   *                     window of the application where the results view will be displayed.
   * @param results      The list of all benchmarking results, in a contiguous sequence, to be
   *                     displayed. These results are grouped and displayed according to the
   *                     corresponding key lengths.
   * @param keyLengths   The list of key lengths, in bits, used in the benchmarking process. Each
   *                     length in this list corresponds to a set of results in the 'results' list.
   *                     This parameter is essential for categorizing the results by key length and
   *                     setting up the key-specific views.
   * @throws IOException If there is an error loading the results view FXML file.
   */
  public void showResultsView(Stage primaryStage, List<Long> results, List<Integer> keyLengths) {

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
      resultsView.setupTableView();
      resultsView.populateTableView();

      splitResultsByKeys();
      displayCurrentContextButtons();
      initialiseKeySwitchButtons();

      resultsView.setLineGraphButtonMeanVisibility(false);
      resultsModel = resultsModels.get(0);
      setStatsResultsView(resultsModel, keyIndex); // Display results for the first key by default

      mainController.setScene(root);
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  /**
   * Displays the results view with options for either standard display or comparison mode. In
   * comparison mode, this method will configure the results view to compare multiple key sizes and
   * the respective results for provably secure vs standard parameters.
   *
   * @param primaryStage                 The primary stage for the application on which the results
   *                                     will be displayed.
   * @param results                      The list of benchmarking results to be displayed.
   * @param keyLengths                   The list of key lengths that were used in the benchmarking
   *                                     process.
   * @param isComparisonMode             Flag indicating whether the comparison mode is active.
   * @param numKeySizesForComparisonMode The number of key sizes that will be compared in comparison
   *                                     mode.
   */
  public void showResultsView(Stage primaryStage, List<Long> results, List<Integer> keyLengths,
      boolean isComparisonMode, int numKeySizesForComparisonMode) {
    if (!isComparisonMode) {
      showResultsView(primaryStage, results, keyLengths);
    } else {

      try {
        FXMLLoader loader = new FXMLLoader(getClass().getResource("/ResultsView.fxml"));
        Parent root = loader.load();
        resultsView = loader.getController();
        this.keyLengths = keyLengths;
        this.totalKeys = this.keyLengths.size();
        this.results = results;
        this.totalTrials = results.size();
        this.trialsPerKey = totalTrials / totalKeys;
        this.numKeySizesForComparisonMode = numKeySizesForComparisonMode;
        this.keyIndex = 0;

        splitResultsByKeys();
        displayCurrentContextButtons();
        initialiseKeySwitchButtonsComparisonMode();

        resultsView.removeValueColumn();
        resultsView.addValueColumns(createComparisonModeColumnHeaders());
        resultsView.setNameColumnText("Parameter Type");

        resultsModel = resultsModels.get(0);
        setStatsResultsView(resultsModel, keyIndex); // Display results for the first key by default
        resultsView.resizeTableView();

        mainController.setScene(root);
      } catch (IOException e) {
        e.printStackTrace();
      }
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
  private CategoryDataset prepareHistogramDatasetForKey(int keyIndex) {
    DefaultCategoryDataset dataset = new DefaultCategoryDataset();
    ResultsModel model = resultsModels.get(keyIndex);

    double q1 = model.getPercentile25Data();
    double q3 = model.getPercentile75Data();
    double binWidth = 2 * ((q3 - q1) / 1E6) * Math.pow(trialsPerKey, -1 / 3.0);

    double min = model.getMinTimeData() / 1E6;
    double max = model.getMaxTimeData() / 1E6;
    int numBins = (int) Math.ceil((max - min) / binWidth);

    // Initialise bin counts
    int[] binCounts = new int[numBins];
    Arrays.fill(binCounts, 0);

    // Count the number of values that fall into each bin
    model.getResults().forEach(ns -> {
      double value = ns / 1E6; // Convert to milliseconds
      int binIndex = (int) ((value - min) / binWidth);
      binIndex = Math.min(binIndex, numBins - 1); // Clamp to the range [0, numBins - 1]
      binCounts[binIndex]++;
    });

    // Add the bin counts to the dataset
    for (int bin = 0; bin < numBins; bin++) {
      double lowerBound = min + (bin * binWidth);
      double upperBound = lowerBound + binWidth;
      String category = String.format("%.1f-%.1f ms", lowerBound, upperBound);
      dataset.addValue(binCounts[bin], "Frequency", category);
    }

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
  private JFreeChart createHistogramFromDataset(CategoryDataset dataset, String title) {
    return ChartFactory.createBarChart(
        title,
        "Time (ms)",
        "Frequency",
        dataset,
        PlotOrientation.VERTICAL,
        false, // no legend needed for a histogram series
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

    dataset.add(createBoxAndWhiskerItem(model), "Key " + keyIndex, "");
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
    String seriesName = "Key " + keyIndex;
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
    CategoryDataset dataset = prepareHistogramDatasetForKey(keyIndex);
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
    return displayBoxPlot(dataset, "Box Plot for " + keyIndex,
        "Key " + (keyIndex + 1) + " (" + keyLengths.get(keyIndex) + "bit)");
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



}
