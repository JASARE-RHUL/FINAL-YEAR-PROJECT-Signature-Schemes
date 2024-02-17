package uk.msci.project.rsa;

import com.jfoenix.controls.JFXTabPane;
import java.net.URL;
import java.util.ResourceBundle;
import javafx.beans.value.ChangeListener;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.Tab;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Region;

/**
 * The {@code ResultsView} class is responsible for displaying the statistical results of the
 * benchmarking process in the digital signature application. It contains elements to visualise
 * various statistics and buttons to export different types of data.
 */
public class ResultsView implements Initializable {

  /**
   * TableView to display statistical data.
   */
  @FXML
  private TableView<StatisticData> tableView;

  /**
   * Label to display a title or heading for the results section.
   */
  @FXML
  private Label resultsLabel;

  /**
   * TableColumn for displaying the name of each statistic.
   */
  @FXML
  private TableColumn<StatisticData, String> nameColumn;

  /**
   * TableColumn for displaying the value of each statistic.
   */
  @FXML
  private TableColumn<StatisticData, String> valueColumn;

  /**
   * Button to navigate back to the main menu.
   */
  @FXML
  private Button backToMainMenuButton;

  /**
   * Button to export the results of benchmarking.
   */
  @FXML
  private Button exportBenchmarkingResultsBtn;

  /**
   * Button to export a batch of private keys.
   */
  @FXML
  private Button exportPrivateKeyBatchBtn;

  /**
   * Button to export a batch of public keys.
   */
  @FXML
  private Button exportPublicKeyBatchBtn;

  /**
   * Button to export a batch of signatures.
   */
  @FXML
  private Button exportSignatureBatchBtn;

  /**
   * Button to export a batch of recoverable messages.
   */
  @FXML
  private Button exportRecoverableMessageBatchBtn = new Button();

  /**
   * Button to export a batch of non-recoverable messages.
   */
  @FXML
  private Button exportNonRecoverableMessageBatchBtn;

  /**
   * Button to export the results of signature verification.
   */
  @FXML
  private Button exportVerificationResultsBtn;

  /**
   * The sideTabContainer field represents the JFXTabPane container for displaying side tabs
   * corresponding to different keys that will trigger the displaying of their corresponding results.
   */
  @FXML
  private JFXTabPane sideTabContainer;


  /**
   * StatisticData object representing the number of trials in the benchmarking process.
   */
  StatisticData numTrials = new StatisticData("Number of trials:", "XXXX.XX ms");

  /**
   * StatisticData object representing the overall time taken in the benchmarking process.
   */
  StatisticData overallData = new StatisticData("Overall time taken:", "XXXX.XX ms");

  /**
   * StatisticData object representing the mean time taken in the benchmarking process.
   */
  StatisticData meanData = new StatisticData("Mean:", "XXXX.XX ms");

  /**
   * StatisticData object representing the confidence interval in the benchmarking process.
   */
  StatisticData confidenceInterval = new StatisticData("Confidence Interval:", "XXXX.XX ms");

  /**
   * StatisticData object representing the 25th percentile of time measurements in the benchmarking
   * process.
   */
  StatisticData percentile25Data = new StatisticData("25th Percentile:", "XXXX.XX ms");

  /**
   * StatisticData object representing the median time measurement in the benchmarking process.
   */
  StatisticData medianData = new StatisticData("Median:", "XXXX.XX ms");

  /**
   * StatisticData object representing the 75th percentile of time measurements in the benchmarking
   * process.
   */
  StatisticData percentile75Data = new StatisticData("75th Percentile:", "XXXX.XX ms");

  /**
   * StatisticData object representing the range of time measurements in the benchmarking process.
   */
  StatisticData rangeData = new StatisticData("Range:", "XXXX.XX ms");

  /**
   * StatisticData object representing the standard deviation of time measurements in the
   * benchmarking process.
   */
  StatisticData stdDeviationData = new StatisticData("Standard Deviation:", "XXXX.XX ms");

  /**
   * StatisticData object representing the variance of time measurements in the benchmarking
   * process.
   */
  StatisticData varianceData = new StatisticData("Variance:", "XXXX.XX ms");

  /**
   * StatisticData object representing the minimum time measurement in the benchmarking process.
   */
  StatisticData minTimeData = new StatisticData("Minimum Time:", "XXXX.XX ms");

  /**
   * StatisticData object representing the maximum time measurement in the benchmarking process.
   */
  StatisticData maxTimeData = new StatisticData("Maximum Time:", "XXXX.XX ms");

  /**
   * Adds a key switch tab (for switching view of results) to the sideTabContainer.
   *
   * @param keyTab The tab to be added for key switching.
   */
  public void addKeySwitchTab(Tab keyTab){
    sideTabContainer.getTabs().add(keyTab);
  }

  /**
   * Adds an observer for the change in display of key results .
   *
   * @param listener The change listener to be added.
   */
  public void addKeyResultsChangeObserver(ChangeListener<Number> listener) {
    sideTabContainer.getSelectionModel().selectedIndexProperty().addListener(listener);
  }


  /**
   * Registers an observer for the event of exporting benchmarking results.
   *
   * @param observer the event handler to be invoked on export benchmarking results action.
   */
  public void addExportBenchmarkingResultsObserver(EventHandler<ActionEvent> observer) {
    exportBenchmarkingResultsBtn.setOnAction(observer);
  }

  /**
   * Registers an observer for the event of exporting private key batch.
   *
   * @param observer the event handler to be invoked on export private key batch action.
   */
  public void addExportPrivateKeyBatchObserver(EventHandler<ActionEvent> observer) {
    exportPrivateKeyBatchBtn.setOnAction(observer);
  }

  /**
   * Registers an observer for the event of exporting public key batch.
   *
   * @param observer the event handler to be invoked on export public key batch action.
   */
  public void addExportPublicKeyBatchObserver(EventHandler<ActionEvent> observer) {
    exportPublicKeyBatchBtn.setOnAction(observer);
  }

  /**
   * Registers an observer for the event of exporting signature batch.
   *
   * @param observer the event handler to be invoked on export signature batch action.
   */
  public void addExportSignatureBatchObserver(EventHandler<ActionEvent> observer) {
    exportSignatureBatchBtn.setOnAction(observer);
  }

  /**
   * Registers an observer for the event of exporting recoverable message batch.
   *
   * @param observer the event handler to be invoked on export recoverable message batch action.
   */
  public void addExportRecoverableMessageBatchObserver(EventHandler<ActionEvent> observer) {
    exportRecoverableMessageBatchBtn.setOnAction(observer);
  }

  /**
   * Registers an observer for the event of exporting non-recoverable message batch.
   *
   * @param observer the event handler to be invoked on export non-recoverable message batch
   *                 action.
   */
  public void addExportNonRecoverableMessageBatchObserver(EventHandler<ActionEvent> observer) {
    exportNonRecoverableMessageBatchBtn.setOnAction(observer);
  }

  /**
   * Registers an observer for the event of exporting verification results.
   *
   * @param observer the event handler to be invoked on export verification results action.
   */
  public void addExportVerificationResultsObserver(EventHandler<ActionEvent> observer) {
    exportVerificationResultsBtn.setOnAction(observer);
  }


  /**
   * Adjusts the management state of the export benchmarking results button.
   *
   * @param managed The management state to set.
   */
  public void setExportBenchmarkingResultsBtnManaged(boolean managed) {
    exportBenchmarkingResultsBtn.setManaged(managed);
  }

  /**
   * Adjusts the visibility of the export benchmarking results button.
   *
   * @param visible The visibility state to set.
   */
  public void setExportBenchmarkingResultsBtnVisible(boolean visible) {
    exportBenchmarkingResultsBtn.setVisible(visible);
  }

  /**
   * Adjusts the management state of the recoverable Message Batch Button.
   *
   * @param managed The management state to set.
   */
  public void setExportRecoverableMessageBatchBtnManaged(boolean managed) {
    exportRecoverableMessageBatchBtn.setManaged(managed);
  }

  /**
   * Adjusts the visibility of the recoverable Message Batch Button.
   *
   * @param visible The visibility state to set.
   */
  public void setExportRecoverableMessageBatchBtVisible(boolean visible) {
    exportRecoverableMessageBatchBtn.setVisible(visible);
  }

  /**
   * Adjusts the management state of the non-Recoverable Message Batch Button.
   *
   * @param managed The management state to set.
   */
  public void setExportNonRecoverableMessageBatchBtnManaged(boolean managed) {
    exportNonRecoverableMessageBatchBtn.setManaged(managed);
  }

  /**
   * Adjusts the visibility of the non-Recoverable Message Batch Button.
   *
   * @param visible The visibility state to set.
   */
  public void setExportNonRecoverableMessageBatchBtVisible(boolean visible) {
    exportNonRecoverableMessageBatchBtn.setVisible(visible);
  }

  /**
   * Adjusts the management state of the export public key batch button.
   *
   * @param managed The management state to set.
   */
  public void setExportPublicKeyBatchBtnManaged(boolean managed) {
    exportPublicKeyBatchBtn.setManaged(managed);
  }

  /**
   * Adjusts the visibility of the export public key batch button.
   *
   * @param visible The visibility state to set.
   */
  public void setExportPublicKeyBatchBtnVisible(boolean visible) {
    exportPublicKeyBatchBtn.setVisible(visible);
  }

  /**
   * Adjusts the management state of the export signature batch button.
   *
   * @param managed The management state to set.
   */
  public void setExportSignatureBatchBtnManaged(boolean managed) {
    exportSignatureBatchBtn.setManaged(managed);
  }

  /**
   * Adjusts the visibility of the export signature batch button.
   *
   * @param visible The visibility state to set.
   */
  public void setExportSignatureBatchBtnVisible(boolean visible) {
    exportSignatureBatchBtn.setVisible(visible);
  }


  /**
   * Sets the text of the results label to the digital signature operation that benchmarking was
   * performed for.
   *
   * @param text The text to be displayed in the results label.
   */
  public void setResultsLabel(String text) {
    resultsLabel.setText(text);
  }


  /**
   * Adjusts the management state of the export verification results button.
   *
   * @param managed The management state to set.
   */
  public void setExportVerificationResultsBtnManaged(boolean managed) {
    exportVerificationResultsBtn.setManaged(managed);
  }

  /**
   * Adjusts the visibility of the export verification results button.
   *
   * @param visible The visibility state to set.
   */
  public void setExportVerificationResultsBtnVisible(boolean visible) {
    exportVerificationResultsBtn.setVisible(visible);
  }

  /**
   * Adjusts the management state of the export private key batch button.
   *
   * @param managed The management state to set.
   */
  public void setExportPrivateKeyBatchBtnManaged(boolean managed) {
    exportPrivateKeyBatchBtn.setManaged(managed);
  }

  /**
   * Adjusts the visibility of the export private key batch button.
   *
   * @param visible The visibility state to set.
   */
  public void setExportPrivateKeyBatchBtnVisible(boolean visible) {
    exportPrivateKeyBatchBtn.setVisible(visible);
  }


  /**
   * Sets the mean value to be displayed in the results.
   *
   * @param value The mean value, formatted as a String.
   */
  public void setMeanValue(String value) {
    meanData.setStatisticValue(value);
  }

  /**
   * Sets the number of trials to be displayed in the results.
   *
   * @param value The number of trials, formatted as a String.
   */
  public void setNumTrials(String value) {
    numTrials.setStatisticValue(value);
  }

  /**
   * Sets the 25th percentile value to be displayed in the results.
   *
   * @param value The 25th percentile value, formatted as a String.
   */
  public void setPercentile25Value(String value) {
    percentile25Data.setStatisticValue(value);
  }

  /**
   * Sets the median value to be displayed in the results.
   *
   * @param value The median value, formatted as a String.
   */
  public void setMedianValue(String value) {
    medianData.setStatisticValue(value);
  }

  /**
   * Sets the 75th percentile value to be displayed in the results.
   *
   * @param value The 75th percentile value, formatted as a String.
   */
  public void setPercentile75Value(String value) {
    percentile75Data.setStatisticValue(value);
  }

  /**
   * Sets the range value to be displayed in the results.
   *
   * @param value The range value, formatted as a String.
   */
  public void setRangeValue(String value) {
    rangeData.setStatisticValue(value);
  }

  /**
   * Sets the standard deviation value to be displayed in the results.
   *
   * @param value The standard deviation value, formatted as a String.
   */
  public void setStdDeviationValue(String value) {
    stdDeviationData.setStatisticValue(value);
  }

  /**
   * Sets the variance value to be displayed in the results.
   *
   * @param value The variance value, formatted as a String.
   */
  public void setVarianceValue(String value) {
    varianceData.setStatisticValue(value);
  }

  /**
   * Sets the minimum time value to be displayed in the results.
   *
   * @param value The minimum time value, formatted as a String.
   */
  public void setMinTimeValue(String value) {
    minTimeData.setStatisticValue(value);
  }

  /**
   * Sets the maximum time value to be displayed in the results.
   *
   * @param value The maximum time value, formatted as a String.
   */
  public void setMaxTimeValue(String value) {
    maxTimeData.setStatisticValue(value);
  }

  /**
   * Sets the overall data value to be displayed in the results.
   *
   * @param value The overall data value, formatted as a String.
   */
  public void setOverallData(String value) {
    overallData.setStatisticValue(value);
  }

  /**
   * Sets the confidence interval to be displayed in the results.
   *
   * @param value The confidence interval, formatted as a String.
   */
  public void setConfidenceInterval(String value) {
    confidenceInterval.setStatisticValue(value);
  }


  /**
   * Initialises the ResultsView, setting up the table view and populating it with data.
   *
   * @param location  The location used to resolve relative paths for the root object, or null if
   *                  unknown.
   * @param resources The resources used to localize the root object, or null if not localized.
   */
  @Override
  public void initialize(URL location, ResourceBundle resources) {
    setupTableView();
    populateTableView();
  }

  /**
   * Configures the table view, setting up the columns and their properties.
   */
  private void setupTableView() {
    // Configure the columns to use the property names from StatisticData
    nameColumn.setCellValueFactory(new PropertyValueFactory<>("statisticName"));
    valueColumn.setCellValueFactory(new PropertyValueFactory<>("statisticValue"));
  }


  /**
   * Populates the table view with statistical data.
   */
  private void populateTableView() {
    // Add the StatisticData instances to the tableView
    tableView.getItems().clear();
    tableView.getItems().addAll(numTrials,
        overallData, meanData, confidenceInterval, percentile25Data,
        medianData, percentile75Data, rangeData, stdDeviationData,
        varianceData, minTimeData, maxTimeData
    );
    resizeTableView();
  }

  /**
   * Resizes the table view based on the number of items it contains.
   */
  private void resizeTableView() {
    int rows = tableView.getItems().size() + 1; // +1 for the header row
    double rowHeight = 26;
    double tableHeight = rows * rowHeight;
    tableView.setPrefHeight(tableHeight);
    tableView.setMinHeight(Region.USE_PREF_SIZE);
    tableView.setMaxHeight(Region.USE_PREF_SIZE);
  }

  /**
   * Refreshes the results displayed in the table view.
   */
  public void refreshResults() {
    tableView.refresh();
  }

  /**
   * Registers an observer for the back to main menu button action event.
   *
   * @param observer The event handler to observe the action.
   */
  void addBackToMainMenuObserver(EventHandler<ActionEvent> observer) {
    backToMainMenuButton.setOnAction(observer);
  }

}
