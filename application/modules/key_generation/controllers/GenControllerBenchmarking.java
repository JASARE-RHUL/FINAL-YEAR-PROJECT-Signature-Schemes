package uk.msci.project.rsa;

import java.util.Collections;
import java.util.List;
import javafx.application.Platform;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.concurrent.Task;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.stage.Stage;
import javafx.util.Pair;
import uk.msci.project.rsa.GenModelBenchmarking;
import uk.msci.project.rsa.BenchmarkingUtility;
import uk.msci.project.rsa.MainController;
import uk.msci.project.rsa.ResultsControllerNormalBenchmarking;
import uk.msci.project.rsa.MainController;

/**
 * This class extends the AbstractGenController to implement functionality specific to the
 * benchmarking mode of operation. It manages the interactions and data flow for key generation
 * processes when benchmarking performance across different key parameters and configurations is
 * required.
 */
public class GenControllerBenchmarking extends uk.msci.project.rsa.AbstractGenController {


  /**
   * The model component of the MVC pattern that handles the data and business logic for RSA key
   * generation in benchmarking mode.
   */
  GenModelBenchmarking genModel;


  /**
   * The number of trials a tracked benchmarking session should last for
   */
  int numTrials;


  /**
   * An instance of the BenchmarkingUtility class used to manage benchmarking tasks. This utility
   * facilitates the execution and monitoring of tasks related to the benchmarking of key generation
   * processes. It provides methods to initiate benchmarking tasks, update progress, and handle task
   * completion.
   */
  BenchmarkingUtility benchmarkingUtility;


  /**
   * Constructs a GenController with a reference to the MainController.
   *
   * @param mainController The main controller that orchestrates the application flow.
   */
  public GenControllerBenchmarking(MainController mainController) {
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
  public void showBenchmarkingView(Stage primaryStage) {
    genModel = new uk.msci.project.rsa.GenModelBenchmarking();
    loadGenView("/GenView.fxml", () -> {
      setupBenchmarkingObservers(primaryStage);
      genView.addNumKeysObserver(new NumKeysBtnObserver());
    });
  }


  /**
   * Sets up observers for benchmarking related UI elements and actions in the GenView. This method
   * configures event handlers and listeners for user interactions specific to the benchmarking
   * process, such as comparison mode toggles, and cross-parameter benchmarking mode changes. It is
   * used to enable the correct functioning of the GenView in different benchmarking scenarios.
   *
   * @param primaryStage The primary stage of the application, required for some UI actions.
   */
  void setupBenchmarkingObservers(Stage primaryStage) {
    genView.addCrossParameterToggleObserver(
        new CrossBenchmarkingModeChangeObserver(GenControllerBenchmarking.this));
  }


  /**
   * Observer that handles the event when the number of keys button is clicked. This observer is
   * responsible for initiating the process of entering multiple key sizes (comparison mode (custom
   * vs (standard vs provably secure))) ar on a more granular level multiple keys (non comparison
   * mode).
   */
  class NumKeysBtnObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
      int numKeys = 0;
      try {
        numKeys = Integer.parseInt(genView.getNumKeys());
        if (!(numKeys > 0)) {
          throw new NumberFormatException();
        }
      } catch (NumberFormatException e) {
        uk.msci.project.rsa.DisplayUtility.showErrorAlert(
            "Error: Invalid input. Please enter a valid number of keys.");
        return;
      }

      // Show the dynamic fields dialog and check if it was completed successfully
      boolean isFieldsDialogCompleted = genView.showDynamicFieldsDialog(numKeys,
          mainController.getPrimaryStage());
      if (isFieldsDialogCompleted) {
        // Only proceed to show the trials dialog if the fields dialog was completed
        if (genView.showTrialsDialog(mainController.getPrimaryStage())) {
          numTrials = genView.getNumTrials();
          benchmarkingUtility = new uk.msci.project.rsa.BenchmarkingUtility();
          Task<Void> benchmarkingTask = createBenchmarkingTask(numTrials,
              genView.getDynamicKeyData());
          uk.msci.project.rsa.BenchmarkingUtility.beginBenchmarkWithUtility(benchmarkingUtility, "Key Generation",
              benchmarkingTask, GenControllerBenchmarking.this::handleBenchmarkingCompletion,
              mainController.getPrimaryStage());
        }
      }
    }
  }


  /**
   * Handles the completion of the benchmarking task for key generation. This method is called when
   * the benchmarking task successfully completes. It initialises and sets up the ResultsController
   * with the appropriate context (KeyGenerationContext) and displays the results view with the
   * gathered benchmarking data.
   */
  private void handleBenchmarkingCompletion() {
    uk.msci.project.rsa.ResultsControllerNormalBenchmarking resultsController = new ResultsControllerNormalBenchmarking(
        mainController);
    uk.msci.project.rsa.BenchmarkingContext context = new uk.msci.project.rsa.KeyGenerationContext(genModel);
    resultsController.setContext(context);
    if (genModel.generateKeyBatch()) {
      mainController.setProvableKeyBatchForSignatureProcesses(
          genModel.getPrivateKeyBatch(),
          genModel.getPublicKeyBatch(), false,
          false);
    }
    resultsController.showResultsView(Collections.emptyList(),
        genModel.getClockTimesPerTrial(),
        genModel.summedKeySizes(genModel.getKeyParams()), false, 0);
  }


  /**
   * Creates a background task for benchmarking key generation. This task generates keys based on
   * provided parameters and updates the progress bar and label on the UI.
   *
   * @param numTrials The number of trials for key generation.
   * @param keyParams The parameters for key generation, including bit sizes and the small e
   *                  option.
   * @return A Task to execute the benchmarking process in the background.
   */
  Task<Void> createBenchmarkingTask(int numTrials, List<Pair<int[], Boolean>> keyParams) {
    return new Task<>() {
      @Override
      protected Void call() throws Exception {
        genModel.batchGenerateKeys(numTrials, keyParams,
            progress -> Platform.runLater(() -> {
              benchmarkingUtility.updateProgress(progress);
              benchmarkingUtility.updateProgressLabel(String.format("%.0f%%", progress * 100));
            }));
        return null;
      }
    };

  }


  /**
   * Observer for changes in the Cross Benchmarking Mode. This observer handles the toggle event
   * between enabling and disabling cross benchmarking mode. It launches an FXML file with
   * specialised cross-parameter benchmarking options when the toggle is switched on and does not
   * allow a user to switch the toggle on, unless a key in the format expected for the mode and been
   * pre-loaded implicitly through the prior key generation process where the option was selected.
   */
  class CrossBenchmarkingModeChangeObserver implements ChangeListener<Boolean> {


    private final GenControllerBenchmarking genController;


    public CrossBenchmarkingModeChangeObserver(GenControllerBenchmarking genController) {
      this.genController = genController;
    }

    @Override
    public void changed(ObservableValue<? extends Boolean> observableValue, Boolean oldValue,
        Boolean newValue) {
      if (Boolean.TRUE.equals(newValue) && Boolean.FALSE.equals(oldValue)) {
        genController.showCrossBenchmarkingView(mainController.getPrimaryStage());
      } else if (Boolean.FALSE.equals(newValue) && Boolean.TRUE.equals(oldValue)) {
        genController.showBenchmarkingView(mainController.getPrimaryStage());
      }
    }
  }


}
