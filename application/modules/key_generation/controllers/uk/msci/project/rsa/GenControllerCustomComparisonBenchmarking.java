package uk.msci.project.rsa;

import javafx.concurrent.Task;


/**
 * This class extends the GenControllerComparisonBenchmarking to specialise in handling key
 * generation for custom comparison benchmarking scenarios. This controller plays a crucial role in
 * orchestrating the key generation logic when comparing different key parameters/configurations
 * within a benchmarking context. It enables users to define custom key generation parameters or to
 * evaluate performance based on a set of custom-defined parameters.
 */
public class GenControllerCustomComparisonBenchmarking extends GenControllerComparisonBenchmarking {


  /**
   * Constructs a GenController with a reference to the MainController.
   *
   * @param mainController The main controller that orchestrates the application flow.
   */
  public GenControllerCustomComparisonBenchmarking(MainController mainController) {
    super(mainController);
  }


  /**
   * Handles the initiation of benchmarking with custom comparison mode. This method sets up and
   * shows dialogs for entering key sizes and subsequently multiple key configurations for each key
   * size, and if completed successfully, initiates the benchmarking task based on user-specified
   * custom parameters.
   *
   * @param numKeys The number of key sizes specified by the user for the custom benchmarking.
   */
  @Override
  void handleBenchmarkingInitiation(int numKeys) {
    boolean isFieldsDialogCompleted = genView.showDynamicFieldsDialogComparisonMode(numKeys,
        mainController.getPrimaryStage());
    if (isFieldsDialogCompleted) {
      uk.msci.project.rsa.DisplayUtility.showInfoAlert(
          "Keys per Key Size",
          "On the dialog that follows, please enter the number of different key configurations you would like to generate for each key size");
      if (genView.showNumKeyConfigsDialog(mainController.getPrimaryStage())) {
        /**
         * Stores the number of key configurations specified by the user for custom benchmarking.
         */
        int numKeyConfigs = genView.getNumKeyConfigs();
        uk.msci.project.rsa.DisplayUtility.showInfoAlert(
            "Key Configurations",
            "On the dialog that follows, to fulfil the " + numKeyConfigs
                + " key configurations you entered, please input each key configuration as comma separated sequence of fractions whose cumulative sum is one");
        boolean isKeyConfigurationsDialogCompleted = genView.showKeyConfigurationsDialog(
            numKeyConfigs,
            mainController.getPrimaryStage());
        if (isKeyConfigurationsDialogCompleted) {

          if (genView.showTrialsDialog(mainController.getPrimaryStage())) {
            numTrials = genView.getNumTrials();
            benchmarkingUtility = new BenchmarkingUtility();
            Task<Void> benchmarkingTask = createBenchmarkingTask(
                genView.getDynamicKeyConfigurationsData(),
                genView.getDynamicKeySizeData(), numTrials);
            BenchmarkingUtility.beginBenchmarkWithUtility(benchmarkingUtility, "Key Generation",
                benchmarkingTask, () -> {
                  handleBenchmarkingCompletion(
                      genModel.formatCustomKeyConfigurations(
                          genView.getDynamicKeyConfigurationsData()), true);
                  mainController.setKeyConfigToHashFunctionsMapForCustomComparisonMode(
                      genView.getKeyConfigToHashFunctionsMap(), genView.getKeysPerGroup());
                },
                mainController.getPrimaryStage());

          }
        }
      }
    }
  }


}
