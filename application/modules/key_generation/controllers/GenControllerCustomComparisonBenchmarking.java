package uk.msci.project.rsa;

import javafx.concurrent.Task;
import uk.msci.project.rsa.GenControllerComparisonBenchmarking;
import uk.msci.project.rsa.MainController;
import uk.msci.project.rsa.BenchmarkingUtility;

/**
 * This class extends the GenControllerComparisonBenchmarking to specialise
 * in handling key
 * generation for custom comparison benchmarking scenarios. This controller
 * plays a crucial role in
 * orchestrating the key generation logic when comparing different key
 * parameters/configurations
 * within a benchmarking context. It enables users to define custom key
 * generation parameters or to
 * evaluate performance based on a set of custom-defined parameters.
 */
public class GenControllerCustomComparisonBenchmarking extends GenControllerComparisonBenchmarking {


  /**
   * Constructs a GenController with a reference to the MainController.
   *
   * @param mainController The main controller that orchestrates the
   *                       application flow.
   */
  public GenControllerCustomComparisonBenchmarking(MainController mainController) {
    super(mainController);
  }


  /**
   * Handles the initiation of benchmarking with custom comparison mode. This
   * method sets up and
   * shows dialogs for entering key sizes and subsequently multiple key
   * configurations for each key
   * size, and if completed successfully, initiates the benchmarking task
   * based on user-specified
   * custom parameters.
   *
   * @param numKeys The number of key sizes specified by the user for the
   *                custom benchmarking.
   */
  @Override
  void handleBenchmarkingInitiation(int numKeys) {
    // Display a dialog for entering the dynamic fields in comparison mode
    // and check if it was completed successfully
    boolean isFieldsDialogCompleted =
      genView.showDynamicFieldsDialogComparisonMode(numKeys,
        mainController.getPrimaryStage());

    if (isFieldsDialogCompleted) {
      // Show an informational alert about entering the number of key
      // configurations
      uk.msci.project.rsa.DisplayUtility.showInfoAlert(
        "Keys per Key Size",
        "On the dialog that follows, please enter the number of different key" +
          " configurations you would like to generate for each key size");

      // Show a dialog for the number of key configurations and check if it
      // was completed successfully
      if (genView.showNumKeyConfigsDialog(mainController.getPrimaryStage())) {
        // Store the number of key configurations specified by the user
        int numKeyConfigs = genView.getNumKeyConfigs();

        // Show an informational alert about inputting each key configuration
        uk.msci.project.rsa.DisplayUtility.showInfoAlert(
          "Key Configurations",
          "On the dialog that follows, to fulfil the " + numKeyConfigs
            + " key configurations you entered, please input each key " +
            "configuration as comma separated sequence of fractions whose " +
            "cumulative sum is one");

        // Show a dialog for the key configurations and check if it was
        // completed successfully
        boolean isKeyConfigurationsDialogCompleted =
          genView.showKeyConfigurationsDialog(
            numKeyConfigs,
            mainController.getPrimaryStage());

        if (isKeyConfigurationsDialogCompleted) {
          // Show a dialog for entering the number of trials and check if it
          // was completed successfully
          if (genView.showTrialsDialog(mainController.getPrimaryStage())) {
            // Store the number of trials for the benchmarking
            numTrials = genView.getNumTrials();

            // Initialsze the benchmarking utility
            benchmarkingUtility = new BenchmarkingUtility();

            // Create the benchmarking task
            Task<Void> benchmarkingTask = createBenchmarkingTask(
              genView.getDynamicKeyConfigurationsData(),
              genView.getDynamicKeySizeData(), numTrials);

            // Begin benchmarking with the utility, handling task initiation
            // and completion
            BenchmarkingUtility.beginBenchmarkWithUtility(benchmarkingUtility
              , "Key Generation",
              benchmarkingTask, () -> {
                // Handle the completion of the benchmarking process
                handleBenchmarkingCompletion(
                  genModel.formatCustomKeyConfigurations(
                    genView.getDynamicKeyConfigurationsData()), true);

                // Initiates the passing the key configuration groups and
                // their respective hash functions map to signature processes
                mainController.setKeyConfigToHashFunctionsMapForCustomComparisonMode(
                  genView.getKeyConfigToHashFunctionsMap(),
                  genView.getKeysPerGroup());
              },
              mainController.getPrimaryStage());
          }
        }
      }
    }
  }


}
