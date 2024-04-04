package uk.msci.project.rsa;

import java.io.IOException;
import java.util.List;

import javafx.application.Platform;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.geometry.Pos;
import javafx.scene.control.Label;
import javafx.scene.control.Tab;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.layout.VBox;
import uk.msci.project.rsa.ResultsBaseController;
import uk.msci.project.rsa.ResultsModel;
import uk.msci.project.rsa.MainController;
import uk.msci.project.rsa.BenchmarkingContext;
import uk.msci.project.rsa.ResultsTableColumn;
import uk.msci.project.rsa.HashFunctionSelection;
import uk.msci.project.rsa.DigestType;
import uk.msci.project.rsa.StatisticData;
import uk.msci.project.rsa.ResultsUtility;

/**
 * This class manages the results display and interaction logic for the
 * digital signature
 * benchmarking application in standard benchmarking mode based solely on the
 * results ordered by
 * single keys. It integrates the results view and model, handles the
 * generation of result
 * statistics, and manages the export functionalities.
 */
public class ResultsControllerNormalBenchmarking extends ResultsBaseController {


  /**
   * Constructs a new ResultsController with a reference to the MainController.
   *
   * @param mainController The main controller of the application.
   */
  public ResultsControllerNormalBenchmarking(MainController mainController) {
    super(mainController);
  }

  /**
   * Sets up event observers for various actions in the results view, like
   * exporting results and
   * navigating back to the main menu.
   */
  public void setupObservers() {
    super.setupObservers();
    resultsView.addExportBenchmarkingResultsObserver(new ExportBenchmarkingResultsObserver());
  }

  /**
   * Configures the visibility and management of buttons in the results view
   * based on the current
   * benchmarking context.
   */
  @Override
  public void displayCurrentContextButtons() {
    super.displayCurrentContextButtons();
    resultsView.setResultsLabel(currentContext.getResultsLabel(false));
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
  public void showResultsView(List<String> comparisonModeRowHeaders,
                              List<Long> results, List<Integer> keyLengths,
                              boolean isComparisonMode,
                              int numKeySizesForComparisonMode) {
    loadResultsView(keyLengths, results,
      () -> {
        if (results.size() / totalKeys > 1) {
          graphManager.setupComparisonModeGraphObservers(resultsView);
        }
      },
      () -> {
        resultsView.setupTableView();
        resultsView.populateTableView();
        initialiseKeySwitchButtons();
        splitResults();
        if (isSignatureOperationResults) {
          resultsView.addStatisticData(
            new StatisticData("Hash Function:",
              resultsModels.get(0).getHashFunctionName()));
        }
        resultsView.refreshResults();
        // Precompute graphs asynchronously
        if (results.size() / totalKeys > 1) {
          Platform.runLater(() -> graphManager.precomputeGraphs(resultsModels
            , keyLengths));
        }
        resultsView.setLineGraphButtonMeanVisibility(false);
      });
  }

  /**
   * Sets statistical results in the results view based on the data from the
   * provided ResultsModel.
   *
   * @param model The ResultsModel instance containing statistical data to
   *              display.
   */
  public void setStatsResultsView(ResultsModel model, int keyIndex) {
    resultsView.setNumTrials(String.valueOf(model.getNumTrials()));
    resultsView.setMeanValue(String.format("%.5f ms", model.getMeanData()));
    resultsView.setPercentile25Value(String.format("%.5f ms",
      model.getPercentile25Data()));
    resultsView.setMedianValue(String.format("%.5f ms", model.getMedianData()));
    resultsView.setPercentile75Value(String.format("%.5f ms",
      model.getPercentile75Data()));
    resultsView.setRangeValue(String.format("%.5f ms", model.getRangeData()));
    resultsView.setStdDeviationValue(String.format("%.5f ms",
      model.getStdDeviationData()));
    resultsView.setVarianceValue(String.format("%.5f ms²",
      model.getVarianceData()));
    resultsView.setMinTimeValue(String.format("%.5f ms",
      model.getMinTimeData()));
    resultsView.setMaxTimeValue(String.format("%.5f ms",
      model.getMaxTimeData()));
    resultsView.setOverallData(String.format("%.5f ms",
      model.getOverallData()));

    double[] confidenceInterval = model.getConfidenceInterval();
    String confidenceIntervalStr = String.format(
      "95%% with bounds [%.5f, %.5f]",
      confidenceInterval[0],
      confidenceInterval[1]
    );
    resultsView.setConfidenceInterval(confidenceIntervalStr);

    resultsView.refreshResults();
  }


  /**
   * Initialises the key switch buttons in comparison mode. This method sets
   * up the UI components
   * that allow the user to switch between results (standard vs provable
   * parameters) for different
   * key sizes.
   */
  void initialiseKeySwitchButtons() {
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
   * Displays the results for a specific key based on the given key index.
   *
   * @param keyIndex The index of the key for which results are to be displayed.
   */
  public void displayResultsForKey(int keyIndex) {
    this.keyIndex = keyIndex;
    graphManager.setKeyIndex(keyIndex);
    resultsModel = resultsModels.get(keyIndex);
    if (isSignatureOperationResults) {
      resultsView.removeLastRow();
      resultsView.addStatisticData(
        new StatisticData("Hash Function:",
          resultsModel.getHashFunctionName()));
    }
    setStatsResultsView(resultsModel, keyIndex);
  }


  /**
   * Observer for handling the export of benchmarking results. Triggers upon
   * user action to export
   * results to a CSV file.
   */
  class ExportBenchmarkingResultsObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {

      try {
        resultsModel.exportStatisticsToCSV(
          currentContext.getResultsLabel(true) + "_" + keyLengths.get(keyIndex) + "bit.csv");
      } catch (IOException e) {
        e.printStackTrace();
      }
      uk.msci.project.rsa.DisplayUtility.showInfoAlert("Export",
        "Benchmarking Results were successfully exported!");
    }
  }


}
