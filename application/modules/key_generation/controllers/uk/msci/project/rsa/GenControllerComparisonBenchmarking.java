package uk.msci.project.rsa;

import java.util.List;
import javafx.application.Platform;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.concurrent.Task;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.scene.control.RadioButton;
import javafx.scene.control.Toggle;
import javafx.stage.Stage;
import javafx.util.Pair;


/**
 * This class extends the GenControllerBenchmarking to specialise in handling key generation for
 * comparison benchmarking scenarios. This controller plays a crucial role in orchestrating the key
 * generation logic when comparing different key parameters/configurations within a benchmarking
 * context. It enables users to define custom key generation parameters and compare the performance
 * between standard RSA key generation and provably secure RSA key generation methods, or to
 * evaluate performance based on a set of custom-defined parameters.
 */
public class GenControllerComparisonBenchmarking extends GenControllerBenchmarking {


  /**
   * The model component of the MVC pattern that handles the data and business logic for RSA key
   * generation in benchmarking mode.
   */
  GenModelComparisonBenchmarking genModelBenchmarking;


  /**
   * Constructs a GenController with a reference to the MainController.
   *
   * @param mainController The main controller that orchestrates the application flow.
   */
  public GenControllerComparisonBenchmarking(MainController mainController) {
    super(mainController);
  }

  /**
   * Initialises and displays the GenView for the key generation functionality in benchmarking mode.
   * This method loads the GenView FXML file, sets up the necessary model and view components, and
   * configures event handlers and observers for the various UI elements.
   *
   * @param primaryStage The primary stage of the application where the view will be displayed.
   */
  @Override
  public void showCrossBenchmarkingView(Stage primaryStage) {
    genModelBenchmarking = new GenModelComparisonBenchmarking();
    loadGenView("/GenViewCrossBenchmarkingMode.fxml", () -> {
      setupCrossBenchmarkingObservers(primaryStage, genView);
    });
  }

  /**
   * Sets up observers for cross-benchmarking related UI elements and actions in the GenView. This
   * method configures event handlers and listeners for user interactions specific to the
   * cross-benchmarking process. It enables the correct functioning of the GenView in different
   * cross-benchmarking scenarios.
   *
   * @param primaryStage The primary stage of the application, required for some UI actions.
   * @param genView      The GenView instance used for the cross-benchmarking mode.
   */
  void setupCrossBenchmarkingObservers(Stage primaryStage, GenView genView) {
    this.genView = genView;
    setupBenchmarkingObservers(primaryStage);
    genView.addCrossBenchMarkingToggleGroupChangeObserver(new ComparisonModeChangeObserver());
    genView.addNumKeysObserver(new NumKeysBtnObserver());
  }


  /**
   * Observer that handles the event when the number of key sizes button is clicked. Handles the
   * initiation of benchmarking in comparison mode (custom or the provably secure vs standard
   * preset). This method sets up and shows the dynamic field dialog for comparison mode, and if
   * completed successfully, proceeds to show the trials dialog and initiate the benchmarking task.
   */
  class NumKeysBtnObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
      int numKeys = 0;
      try {
        numKeys = Integer.parseInt(genView.getNumKeys());
      } catch (NumberFormatException e) {
        uk.msci.project.rsa.DisplayUtility.showErrorAlert(
            "Error: Invalid input. Please enter a valid number of keys.");
        return;
      }
      handleBenchmarkingInitiation(numKeys);

    }
  }


  /**
   * Handles the completion of the benchmarking task for key generation in comparison mode. This
   * method is called when the benchmarking task successfully completes. It initialises and sets up
   * the ResultsController with the appropriate context and displays the results view with the
   * gathered benchmarking data.
   */
  void handleBenchmarkingCompletion(List<String> keyConfigurationsString,
      boolean isCustomComparisonMode) {

    ResultsControllerComparisonBenchmarking resultsController = new ResultsControllerComparisonBenchmarking(
        mainController);
    BenchmarkingContext context = new KeyGenerationContext(genModelBenchmarking);
    resultsController.setContext(context);
    genModelBenchmarking.generateKeyBatch();
    mainController.setProvableKeyBatchForSignatureProcesses(
        genModelBenchmarking.getPrivateKeyBatch(),
        genModelBenchmarking.getPublicKeyBatch(), true,
        isCustomComparisonMode);
    mainController.setKeyConfigurationStringsForComparisonMode(keyConfigurationsString);
    resultsController.showResultsView(keyConfigurationsString,
        genModelBenchmarking.getClockTimesPerTrial(),
        genModelBenchmarking.summedKeySizes(genModelBenchmarking.getKeyParams()), true,
        genModelBenchmarking.getNumKeySizesForComparisonMode());
  }

  /**
   * Handles the initiation of benchmarking in comparison mode. This method sets up and shows the
   * dynamic fields dialog for comparison mode, and if completed successfully, proceeds to show the
   * trials dialog and initiate the benchmarking task.
   *
   * @param numKeys The number of key sizes specified by the user for the comparison benchmarking.
   */
  void handleBenchmarkingInitiation(int numKeys) {
    // Show the dynamic fields dialog and check if it was completed successfully
    boolean isFieldsDialogCompleted = genView.showDynamicFieldsDialogComparisonMode(numKeys,
        mainController.getPrimaryStage());
    if (isFieldsDialogCompleted) {
      // Only proceed to show the trials dialog if the fields dialog was completed
      if (genView.showTrialsDialog(mainController.getPrimaryStage())) {
        numTrials = genView.getNumTrials();
        benchmarkingUtility = new BenchmarkingUtility();
        Task<Void> benchmarkingTask = createBenchmarkingTask(
            genModelBenchmarking.getDefaultKeyConfigurationsData(),
            genView.getDynamicKeySizeData(), numTrials);
        BenchmarkingUtility.beginBenchmarkWithUtility(benchmarkingUtility, "Key Generation",
            benchmarkingTask, () -> handleBenchmarkingCompletion(
                genModelBenchmarking.formatDefaultKeyConfigurations(), false),
            mainController.getPrimaryStage());
      }
    }
  }


  /**
   * Creates a background task for benchmarking key generation in comparison mode. This task
   * generates keys based on provided custom key configurations and key sizes, and updates the
   * progress bar and label on the UI. This mode allows comparing key generation across different
   * custom configurations.
   *
   * @param keyConfigurationsData Custom configurations for key generation.
   * @param keyParams             List of key sizes for benchmarking.
   * @param numTrials             The number of trials for each key configuration.
   * @return A Task to execute the benchmarking process in the background.
   */
  Task<Void> createBenchmarkingTask(
      List<Pair<int[], Boolean>> keyConfigurationsData, List<Integer> keyParams, int numTrials) {

    return new Task<>() {
      @Override
      protected Void call() {
        genModelBenchmarking.batchGenerateKeysInComparisonMode(keyConfigurationsData,
            keyParams, numTrials,
            progress -> Platform.runLater(() -> {
              benchmarkingUtility.updateProgress(progress);
              benchmarkingUtility.updateProgressLabel(String.format("%.0f%%", progress * 100));
            }));
        return null;
      }
    };

  }


  /**
   * Observer for selecting the comparison mode in the GenView. This class listens to changes in the
   * comparison mode toggle group and updates the GenView UI elements based on the selected mode.
   */
  class ComparisonModeChangeObserver implements ChangeListener<Toggle> {

    @Override
    public void changed(ObservableValue<? extends Toggle> observable, Toggle oldValue,
        Toggle newValue) {
      if (newValue != null) {
        RadioButton selectedRadioButton = (RadioButton) newValue;
        String radioButtonText = selectedRadioButton.getText();
        switch (radioButtonText) {
          case "Compare Custom Parameters":
            mainController.activateKeyGenCustomComparisonMode(genView);
            break;
          case "Compare Standard vs Provably secure":
            mainController.activateKeyGenComparisonMode(genView);
          default:
            break;

        }
      }
    }
  }


}
