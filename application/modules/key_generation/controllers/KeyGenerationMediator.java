package uk.msci.project.rsa;

import uk.msci.project.rsa.MainController;
import uk.msci.project.rsa.GenControllerStandard;
import uk.msci.project.rsa.GenControllerBenchmarking;
import uk.msci.project.rsa.GenControllerComparisonBenchmarking;
import uk.msci.project.rsa.GenView;

/**
 * This class acts as an intermediary between the main controller of the
 * application and the key
 * generation controller assembly. It handles the setup and coordination of
 * key generation across
 * different operational modes, including standard, benchmarking, and
 * comparison benchmarking. This
 * class ensures the appropriate controllers are utilised and configured
 * based on the operational
 * context and mode.
 */
public class KeyGenerationMediator {

  /**
   * Main controller instance to manage transitions between different
   * application views and
   * high-level logic execution.
   */
  private MainController mainController;

  /**
   * Controller for handling key generation functionality in standard mode.
   */
  private GenControllerStandard genControllerStandard;

  /**
   * Controller for handling key generation functionality in benchmarking mode.
   */
  private GenControllerBenchmarking genControllerBenchmarking;

  /**
   * Controller for handling key generation functionality in comparison
   * benchmarking mode.
   */
  private GenControllerComparisonBenchmarking genControllerComparisonBenchmarking;

  /**
   * Constructor that initialises a new KeyGenerationMediator with a
   * reference to the main
   * application controller.
   *
   * @param mainController The central controller that coordinates the flow
   *                       of the application.
   */
  public KeyGenerationMediator(MainController mainController) {
    this.mainController = mainController;
    genControllerStandard = new GenControllerStandard(mainController);
    genControllerBenchmarking = new GenControllerBenchmarking(mainController);
    genControllerComparisonBenchmarking =
      new GenControllerComparisonBenchmarking(mainController);
  }

  /**
   * Retrieves the controller responsible for key generation benchmarking.
   *
   * @return The benchmarking mode key generation controller.
   */
  public GenControllerBenchmarking getGenControllerBenchmarking() {
    return genControllerBenchmarking;
  }

  /**
   * Retrieves the controller responsible for key generation in standard mode.
   *
   * @return The standard mode key generation controller.
   */
  public GenControllerStandard getGenControllerStandard() {
    return genControllerStandard;
  }

  /**
   * Retrieves the controller responsible for key generation in comparison
   * benchmarking mode.
   *
   * @return The comparison benchmarking mode key generation controller.
   */
  public GenControllerComparisonBenchmarking getGenControllerComparisonBenchmarking() {
    return genControllerComparisonBenchmarking;
  }

  /**
   * Triggers the display of the standard key generation view.
   */
  public void showStandardView() {
    genControllerStandard.showStandardView(mainController.getPrimaryStage());
  }

  /**
   * Triggers the display of the benchmarking key generation view.
   */
  public void showBenchmarkingView() {
    genControllerBenchmarking.showBenchmarkingView(mainController.getPrimaryStage());
  }

  /**
   * Triggers the display of the comparison benchmarking key generation view.
   */
  public void showCrossBenchmarkingView() {
    genControllerComparisonBenchmarking.showCrossBenchmarkingView(mainController.getPrimaryStage());
  }

  /**
   * Sets the GenControllerComparisonBenchmarking instance for the mediator
   * and facilitates a switch
   * between normal comparison mode and custom comparison mode.
   *
   * @param genControllerComparisonBenchmarking The instance of
   *                                            GenControllerComparisonBenchmarking
   *                                            to be set.
   * @param genView                             The GenView instance
   *                                            associated with the comparison
   *                                            benchmarking mode.
   */
  public void setGenControllerComparisonBenchmarking(
    GenControllerComparisonBenchmarking genControllerComparisonBenchmarking,
    GenView genView) {
    this.genControllerComparisonBenchmarking =
      genControllerComparisonBenchmarking;
    this.genControllerComparisonBenchmarking.setupCrossBenchmarkingObservers(
      mainController.getPrimaryStage(), genView);
  }
}
