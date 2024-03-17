package uk.msci.project.rsa;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import javafx.application.Platform;
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


/**
 * This class manages the results display and interaction logic for the digital signature
 * benchmarking application. It integrates the results view and model, handles the generation of
 * result statistics, and manages the export functionalities.
 */
public class ResultsControllerComparisonBenchmarking extends ResultsBaseController {

  /**
   * Constructs a new ResultsController with a reference to the MainController.
   *
   * @param mainController The main controller of the application.
   */
  public ResultsControllerComparisonBenchmarking(MainController mainController) {
    super(mainController);
  }


  /**
   * Sets up event observers for various actions in the results view, like exporting results and
   * navigating back to the main menu.
   */
  public void setupObservers() {
    super.setupObservers();
    resultsView.addExportBenchmarkingResultsObserver(new ExportBenchmarkingResultsObserver());
  }


  /**
   * Configures the visibility and management of buttons in the results view based on the current
   * benchmarking context.
   */
  @Override
  public void displayCurrentContextButtons() {
    super.displayCurrentContextButtons();
    if (isSignatureOperationResults) {
      resultsView.setResultsLabel(currentContext.getResultsLabel(true));
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
   * @param results                      List of benchmarking results, ordered by keys. Each entry
   *                                     in the list represents the result of a benchmarking trial.
   * @param keyLengths                   List of key lengths used in the benchmarking process.
   * @param isComparisonMode             Flag indicating whether the comparison mode is active.
   * @param numKeySizesForComparisonMode Number of key sizes to be compared in comparison mode. This
   *                                     parameter is relevant only if 'isComparisonMode' is true
   *                                     and dictates how the results are organized and displayed
   */
  public void showResultsView(List<String> comparisonModeRowHeaders,
      List<Long> results, List<Integer> keyLengths,
      boolean isComparisonMode, int numKeySizesForComparisonMode) {
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
            splitResults();
          } else {
            super.splitResults();
          }
          initialiseKeySwitchButtons();
          resultsView.addValueColumns(createComparisonModeColumnHeaders());
          // Precompute graphs asynchronously
          Platform.runLater(() -> graphManager.precomputeGraphsComparisonMode(resultsModels, comparisonModeRowHeaders,
              results, keyLengths));
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
  @Override
  void splitResults() {
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
   * Sets statistical results in the results view based on the data from the provided ResultsModel.
   *
   * @param model The ResultsModel instance containing statistical data to display.
   */
  public void setStatsResultsView(ResultsModel model, int keyIndex) {
    resultsView.clearTableView();
    for (StatisticData data : prepareComparisonData(keyIndex)) {
      resultsView.addStatisticData(data);
    }

    resultsView.refreshResults();
  }


  /**
   * Initialises the key switch buttons in comparison mode. This method sets up the UI components
   * that allow the user to switch between results (standard vs provable parameters) for different
   * key sizes.
   */
  void initialiseKeySwitchButtons() {
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
   * Displays the results for a specific key based on the given key index.
   *
   * @param keyIndex The index of the key for which results are to be displayed.
   */
  public void displayResultsForKey(int keyIndex) {
    this.keyIndex = keyIndex;
    graphManager.setKeyIndex(keyIndex);
    resultsModel = resultsModels.get(keyIndex);
    setStatsResultsView(resultsModel, keyIndex);
  }


  /**
   * Observer for handling the export of benchmarking results. Triggers upon user action to export
   * results to a CSV file.
   */
  class ExportBenchmarkingResultsObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
      resultsView.exportComparisonTableResultsToCSV(
          currentContext.getResultsLabel(true) + "_" + ResultsUtility.getKeyLength(keyIndex,
              resultsModels, numKeySizesForComparisonMode, keyLengths) + "bit_key_size_"
              + "_comparisonMode.csv");
      uk.msci.project.rsa.DisplayUtility.showInfoAlert("Export",
          "Benchmarking Results were successfully exported!");
    }
  }


}
