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
import javafx.scene.Scene;
import javafx.scene.control.Button;
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
   * Displays the results view and initializes the results model with the provided benchmarking
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

      splitResultsByKeys();

      displayCurrentContextButtons();
      initialiseKeySwitchButtons();
      resultsModel = resultsModels.get(0);
      setStatsResultsView(resultsModel); // Display results for the first key by default
      setupObservers();
      mainController.setScene(root);
    } catch (IOException e) {
      e.printStackTrace();
    }
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
    setStatsResultsView(resultsModel);
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
  public void setStatsResultsView(ResultsModel model) {
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
   * Initializes key switch buttons in the results view for selecting different keys' results. Each
   * button corresponds to one key and its associated results.
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
        resultsModel.exportStatisticsToCSV(
            currentContext.getResultsLabel() + "_" + keyLengths.get(keyIndex) + "bit.csv");
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
        resultsView.refreshResults();
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
            "The signature batch was successfully exported. Warning: The Signature batch is inclusive signatures corresponding to all keys submitted for this session");
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
