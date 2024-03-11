package uk.msci.project.rsa;


import java.util.List;
import java.util.Map;

/**
 * Thus class class acts as an intermediary between the main controller of the application and
 * various signature controllers. It handles the setup and coordination of signature creation and
 * verification processes across different operational modes, including standard, benchmarking, and
 * comparison benchmarking. This class ensures the appropriate controllers are utilized and
 * configured based on the operational context and mode.
 */
public class SignatureMediator {

  /**
   * The main controller of the application. This controller coordinates overall application flow,
   * including transitioning between different views and executing high-level application logic.
   */
  MainController mainController;

  /**
   * Controller for the signature creation functionality in standard mode. Manages the logic and
   * view related to creating digital signatures in a non-benchmarking context.
   */
  AbstractSignatureBaseController signatureControllerStandard;

  /**
   * Controller for the signature creation functionality in benchmarking mode. Handles the process
   * of creating digital signatures in a context where performance benchmarking is a priority.
   */
  AbstractSignatureBaseControllerBenchmarking signatureControllerBenchmarking;

  /**
   * Controller for the signature creation functionality in benchmarking mode. Handles the process
   * of creating digital signatures in a context where performance benchmarking is a priority.
   */
  AbstractSignatureBaseControllerBenchmarking signatureControllerComparisonBenchmarking;


  /**
   * Constructs a SignatureMediator with a reference to the main controller of the application. It
   * initialises the standard and benchmarking mode controllers for signature verification or
   * creation.
   *
   * @param mainController The main controller of the application, responsible for overall
   *                       application flow.
   */
  public SignatureMediator(MainController mainController) {
    this.mainController = mainController;
  }


  /**
   * Returns the standard mode signature controller. This controller is responsible for managing
   * signature creation or verification in standard mode.
   *
   * @return The standard mode signature controller.
   */
  public AbstractSignatureBaseController getSignatureControllerStandard() {
    return signatureControllerStandard;
  }

  /**
   * Returns the benchmarking mode signature controller. This controller is responsible for managing
   * signature creation or verification in benchmarking mode.
   *
   * @return The benchmarking mode signature controller.
   */
  public AbstractSignatureBaseControllerBenchmarking getSignatureControllerBenchmarking() {
    return signatureControllerBenchmarking;
  }

  /**
   * Returns the comparison benchmarking mode signature controller. This controller is responsible
   * for managing signature creation or verification in cross-parameter benchmarking mode.
   *
   * @return The cross parameter benchmarking mode signature controller.
   */
  public AbstractSignatureBaseControllerBenchmarking getSignatureControllerComparisonBenchmarking() {
    return signatureControllerComparisonBenchmarking;
  }


  /**
   * Sets the batch of private and public keys for a signature process. This method is crucial for
   * handling the application's functionality in different modes, specifically in comparison and
   * custom comparison benchmarking modes. It delegates the process of setting keys for the
   * signature creation and verification controllers, allowing these controllers to operate with the
   * specified keys.
   * <p>
   * In comparison mode, this method helps in setting up the environment for comparing the standard
   * vs provably secure parameters. In custom comparison mode, it facilitates a more granular and
   * detailed analysis with arbitrary user provided key configurations.
   *
   * @param keyBatch                     The batch of private keys used in the signature creation
   *                                     process. process.
   * @param isKeyForComparisonMode       Indicates if the keys are used in comparison mode, enabling
   *                                     performance comparison.
   * @param isKeyForCustomComparisonMode Indicates if the keys are set for custom comparison mode,
   *                                     enabling detailed analysis with custom configurations.
   */
  public void setProvableKeyBatchForSignatureProcesses(String keyBatch,
      boolean isKeyForComparisonMode, boolean isKeyForCustomComparisonMode) {
    if (isKeyForComparisonMode) {
      signatureControllerComparisonBenchmarking.importKeyFromKeyGeneration(keyBatch,
          isKeyForComparisonMode);
      signatureControllerComparisonBenchmarking.setIsCustomCrossParameterBenchmarkingMode(
          isKeyForCustomComparisonMode);
    } else {
      signatureControllerBenchmarking.importKeyFromKeyGeneration(keyBatch,
          isKeyForComparisonMode);
    }


  }


  /**
   * Sets the private/public key for signature verification/creation operations. This method is used
   * to provide the signature controller with a provably secure generated (small e ) key pairing to
   * allow for later instantiation of a signature scheme with provably secure parameters. The key
   * pairing can be set in non-benchmarking mode.
   */
  public void setProvableKeyForSignatureProcesses(String key) {
    signatureControllerStandard.importSingleKeyFromKeyGeneration(key);
  }


  /**
   * Sets the list of key configuration strings for comparison mode signature controller operation
   * by providing configuration details of the keys used in the comparison benchmarking mode. The
   * configuration strings represent different key configurations that are used to compare signature
   * processes under different key settings.
   *
   * @param keyConfigurationStringsForComparisonMode A list of string representations of key
   *                                                 configurations.
   */
  public void setKeyConfigurationStringsForComparisonMode(
      List<String> keyConfigurationStringsForComparisonMode) {
    signatureControllerComparisonBenchmarking.setKeyConfigurationStrings(
        keyConfigurationStringsForComparisonMode);
  }

  /**
   * Sets the mapping of key configurations to hash functions for the custom comparison mode in
   * signature creation or verification controller. This method allows for specifying different hash
   * functions for each group of key configurations.
   *
   * @param keyConfigToHashFunctionsMap The map linking each key configuration group to its hash
   *                                    function selections.
   * @param keyPerGroup                 The number of keys per group, determining how many keys are
   *                                    processed together.
   */
  public void setKeyConfigToHashFunctionsMapForCustomComparisonMode(
      Map<Integer, List<HashFunctionSelection>> keyConfigToHashFunctionsMap, int keyPerGroup) {
    signatureControllerComparisonBenchmarking.setKeyConfigToHashFunctionsMap(
        keyConfigToHashFunctionsMap,
        keyPerGroup);
  }


  /**
   * Displays the signature view in standard mode. This method triggers the UI update to show the
   * interface for signature operations in standard mode.
   */
  public void showSignatureViewStandard() {
    signatureControllerStandard.showStandardView(mainController.getPrimaryStage());
  }

  /**
   * Displays the signature view in standard mode. This method triggers the UI update to show the
   * interface for signature operations in standard mode.
   */
  public void showSignatureViewComparisonBenchmarking() {
    signatureControllerComparisonBenchmarking.showCrossBenchmarkingView(
        mainController.getPrimaryStage());
  }


  /**
   * Displays the signature view in benchmarking mode. This method triggers the UI update to show
   * the interface for signature operations with performance benchmarking functionalities.
   */
  public void showSignatureViewBenchmarking() {
    signatureControllerBenchmarking.showBenchmarkingView(mainController.getPrimaryStage());
  }

  /**
   * Checks if the single key set in the standard controller is provably secure.
   *
   * @return True if the single key is provably secure, false otherwise.
   */
  public boolean getIsSingleKeyProvablySecure() {
    return signatureControllerStandard.getIsSingleKeyProvablySecure();
  }

  /**
   * Retrieves the imported key batch used in comparison benchmarking mode. This method is essential
   * for accessing the batch of keys that have been loaded for conducting performance comparisons
   * across different cryptographic parameters. It's especially useful in scenarios where the
   * signature creation or verification processes need to operate with a predefined set of keys to
   * facilitate comparison across different key sizes and configurations.
   *
   * @return A String representation of the imported key batch for comparison benchmarking mode.
   * Returns null if no key batch has been imported.
   */
  public String getComparisonBenchmarkingImport() {
    return signatureControllerComparisonBenchmarking.getImportedKeyBatch();
  }


}
