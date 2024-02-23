package uk.msci.project.rsa;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
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
      resultsModel = resultsModels.get(0);
      setStatsResultsView(resultsModel, keyIndex); // Display results for the first key by default
      setupObservers();
      mainController.setScene(root);
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  /**
   * Displays the results view with options for either standard display or comparison mode.
   * In comparison mode, this method will configure the results view to compare multiple
   * key sizes and the respective results for provably secure vs standard parameters.
   *
   * @param primaryStage                 The primary stage for the application on which the results will be displayed.
   * @param results                      The list of benchmarking results to be displayed.
   * @param keyLengths                   The list of key lengths that were used in the benchmarking process.
   * @param isComparisonMode             Flag indicating whether the comparison mode is active.
   * @param numKeySizesForComparisonMode The number of key sizes that will be compared in comparison mode.
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

        resultsView.removeValueColumn();
        resultsView.addValueColumns(createComparisonModeColumnHeaders());
        resultsView.setNameColumnText("Parameter Type");

        displayCurrentContextButtons();
        initialiseKeySwitchButtonsComparisonMode();
        resultsModel = resultsModels.get(0);
        setStatsResultsView(resultsModel, keyIndex); // Display results for the first key by default
        resultsView.resizeTableView();

        setupObservers();
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
    resultsView.setExportSignatureBatchBtnVisible(currentContext.showExportSignatureBatchButton());
    resultsView.setExportSignatureBatchBtnManaged(currentContext.showExportSignatureBatchButton());
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
      comparisonData.add(new StatisticData(getComparisonModeRowHeader(i % NUM_ROWS_COMPARISON_MODE),
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
   * that allow the user to switch between results (standard vs provable parameters) for different key sizes.
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

}
