package uk.msci.project.rsa;

import java.io.IOException;
import java.util.List;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
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
   * results. Configures the view based on the current benchmarking context.
   *
   * @param primaryStage The primary stage on which the view is to be set.
   * @param results      The list of benchmarking results to display.
   */
  public void showResultsView(Stage primaryStage, List<Long> results) {
    try {
      FXMLLoader loader = new FXMLLoader(getClass().getResource("/ResultsView.fxml"));
      Parent root = loader.load();
      resultsView = loader.getController();
      resultsModel = new ResultsModel(results);
      resultsModel.calculateStatistics();

      displayCurrentContextButtons();

      setStatsResultsView();
      setupObservers();

      primaryStage.setScene(new Scene(root));

    } catch (IOException e) {
      e.printStackTrace();
    }
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
    resultsView.setExportRecoverableMessageBatchBtVisible(
        currentContext.showRecoverableBatchButton());
    resultsView.setExportRecoverableMessageBatchBtnManaged(
        currentContext.showRecoverableBatchButton());
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
    resultsView.addExportRecoverableMessageBatchObserver(
        new ExportRecoverableMessageBatchObserver());

  }

  /**
   * Sets statistical results on the results view based on the data calculated in the results
   * model.
   */
  public void setStatsResultsView() {
    resultsView.setNumTrials(String.valueOf(resultsModel.getNumTrials()));
    resultsView.setMeanValue(String.format("%.2f ms", resultsModel.getMeanData()));
    resultsView.setPercentile25Value(String.format("%.2f ms", resultsModel.getPercentile25Data()));
    resultsView.setMedianValue(String.format("%.2f ms", resultsModel.getMedianData()));
    resultsView.setPercentile75Value(String.format("%.2f ms", resultsModel.getPercentile75Data()));
    resultsView.setRangeValue(String.format("%.2f ms", resultsModel.getRangeData()));
    resultsView.setStdDeviationValue(String.format("%.2f ms", resultsModel.getStdDeviationData()));
    resultsView.setVarianceValue(String.format("%.2f ms²", resultsModel.getVarianceData()));
    resultsView.setMinTimeValue(String.format("%.2f ms", resultsModel.getMinTimeData()));
    resultsView.setMaxTimeValue(String.format("%.2f ms", resultsModel.getMaxTimeData()));
    resultsView.setOverallData(String.format("%.2f ms", resultsModel.getOverallData()));

    double[] confidenceInterval = resultsModel.getConfidenceInterval();
    String confidenceIntervalStr = String.format(
        "95%% with bounds [%.2f, %.2f]",
        confidenceInterval[0],
        confidenceInterval[1]
    );
    resultsView.setConfidenceInterval(confidenceIntervalStr);
  }

  /**
   * Observer for handling the export of benchmarking results. Triggers upon user action to export
   * results to a CSV file.
   */
  class ExportBenchmarkingResultsObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
      try {
        resultsModel.exportStatisticsToCSV(currentContext.getResultsLabel());
        uk.msci.project.rsa.DisplayUtility.showInfoAlert("Export",
            "Benchmarking Results were successfully exported!");
      } catch (IOException e) {
        e.printStackTrace();
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
            "The signature batch was successfully exported!");
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
   * Observer for handling the export of a recoverable Message batch. Triggers upon user action to
   * export the recoverable batch.
   */
  class ExportRecoverableMessageBatchObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
      currentContext.exportRecoverableMessages();
      uk.msci.project.rsa.DisplayUtility.showInfoAlert("Export",
          "The recovered message batch was successfully exported!");
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
      resultsView = null;
    }
  }

}
