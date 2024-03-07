package uk.msci.project.rsa;

import java.util.List;
import java.util.Map;

/**
 * SignatureBaseContext serves as an abstract base class for contexts associated with signature
 * operations for the benchmarking results module. This class extends from BenchmarkingContext,
 * providing additional functionalities and abstract methods specifically tailored for signature
 * operations, result labelling, and export functionalities. Implementations of this class are
 * expected to define specific behaviours for different types of signature operations (creation,
 * verification, etc.) for use in the results module and handle data and logic related to these
 * operations.
 *
 * <p>It encapsulates a SignatureModel, which contains the core logic and data for signature
 * operations, enabling subclasses to interact with and manipulate signature-related data.
 * Furthermore, this class provides methods to interface with the model.
 */
public abstract class SignatureBaseContext extends BenchmarkingContext {

  /**
   * The model associated with signature creation that contains logic and data for the operation.
   */
  SignatureModel signatureModel;

  /**
   * Constructs a SignatureBaseContext with the specified SignatureModel.
   *
   * @param signatureModel The model containing signature creation or verification logic and data.
   */
  public SignatureBaseContext(SignatureModel signatureModel) {
    this.signatureModel = signatureModel;
  }

  /**
   * Provides a context-specific label for the results view based on the specific signature
   * operation that was benchmarked. This label is used to display relevant information about the
   * benchmarking context in the UI, offering users a clear understanding of the results being
   * presented. The label can vary depending on whether the benchmarking is conducted in normal
   * benchmarking mode displaying the single hash function used, differing from comparison mode
   * where multiple hash functions can potentially be used so the hash function name is omitted from
   * label.
   *
   * @param isComparisonMode A boolean flag indicating whether the benchmarking is done in
   *                         comparison mode, which may affect the label content.
   * @return A string label describing the benchmarking results for signature generation.
   */
  @Override
  public String getResultsLabel(boolean isComparisonMode) {
    return getSignatureResultsLabel(isComparisonMode);
  }

  /**
   * Provides a label for the results of signature operations in the context, tailored to reflect
   * whether the operations were carried out in comparison mode and the type of signature operation
   * performed. In comparison mode, the label includes only the type of signature operation and the
   * signature type, as multiple hash functions may be involved. In normal benchmarking mode, the
   * label also includes the hash function used.
   *
   * @param isComparisonMode       Indicates whether the operations were conducted in comparison
   *                               mode.
   * @param signatureOperationText The text representing the type of signature operation (e.g.,
   *                               "Creation", "Verification").
   * @return A descriptive label for the signature operation results.
   */
  public String getSignatureResultsLabel(boolean isComparisonMode, String signatureOperationText) {
    return isComparisonMode ? "Benchmarking Results for Signature " + signatureOperationText + " ("
        + signatureModel.getSignatureType() + ")"
        : "Benchmarking Results for Signature " + signatureOperationText + " ("
            + signatureModel.getSignatureType() + "-" + signatureModel.getHashType() + ")";
  }


  /**
   * Abstract method to be implemented by subclasses for providing a label for the results of
   * signature operations. The label's content depends on the implementation in the subclass and the
   * mode of operation (comparison benchmarking or normal benchmarking). In comparison mode, the
   * label includes only the type of signature operation and the * signature type, as multiple hash
   * functions may be involved. In normal benchmarking mode, the * label also includes the hash
   * function used.
   *
   * @param isComparisonMode Indicates whether the operations were conducted in comparison mode.
   * @return A descriptive label for the signature operation results.
   */
  public abstract String getSignatureResultsLabel(boolean isComparisonMode);


  /**
   * Retrieves a map linking each group index to its corresponding list of hash functions and their
   * provable security status.
   *
   * @return A map where each key is a group index and each value is a list of pairs of {@code
   * DigestType} and a boolean indicating if it's provably secure.
   */
  @Override
  public Map<Integer, List<HashFunctionSelection>> getKeyConfigToHashFunctionsMap() {
    return signatureModel.getKeyConfigToHashFunctionsMap();
  }

  /**
   * Retrieves the number of keys considered as a group in the signature benchmarking context. This
   * grouping is relevant for applying different hash functions and parameters during the
   * benchmarking process.
   *
   * @return The number of keys per group used in the benchmarking.
   */
  public int getKeysPerGroup() {
    return signatureModel.getKeysPerGroup();
  }

  /**
   * Provides an array representing the number of trials performed for each key within a group in
   * the context of signature benchmarking.
   *
   * @return An array where each element corresponds to the number of trials for a key in a specific
   * group.
   */
  @Override
  public int[] getTrialsPerKeyByGroup() {
    return signatureModel.getTrialsPerKeyByGroup();
  }

  /**
   * Retrieves the total number of hash functions used across all groups in the signature
   * benchmarking.
   *
   * @return The total number of hash functions used in the benchmarking process.
   */
  @Override
  public int getTotalHashFunctions() {
    return signatureModel.getTotalHashFunctions();
  }

  /**
   * Gets the total number of distinct groups formed for the purpose of signature benchmarking. Each
   * group represents a unique combination of key configurations or hash functions.
   *
   * @return The total number of groups in the benchmarking process.
   */
  @Override
  public int getTotalGroups() {
    return signatureModel.getTotalGroups();
  }

  /**
   * Retrieves the fraction used to calculate the custom hash size based on provided key lengths in
   * normal benchmarking mode.
   *
   * @return corresponding fraction represented as an int list
   */
  @Override
  public int[] getCustomHashSizeFraction() {
    return signatureModel.getCustomHashSizeFraction();
  }

  /**
   * Retrieves the type of hash function currently set in the model.
   *
   * @return The current hash function type.
   */
  @Override
  public DigestType getHashType() {
    return signatureModel.getHashType();
  }

  /**
   * Indicates whether the signature scheme operates in provably secure mode.
   *
   * @return {@code true} if the signature scheme is operating in provably secure mode, {@code
   * false} otherwise.
   */
  public boolean getProvablySecure() {
    return signatureModel.getProvablySecure();
  }
}
