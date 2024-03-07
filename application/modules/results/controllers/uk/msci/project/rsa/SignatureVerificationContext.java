package uk.msci.project.rsa;

import java.io.IOException;
import java.util.List;
import java.util.Map;

/**
 * This class is a specialised context for the benchmarking of signature verification operations. It
 * extends BenchmarkingContext to provide functionality specific to signature verification, such as
 * exporting verification decisions to the generalised results view.
 */
public class SignatureVerificationContext extends BenchmarkingContext {

  private SignatureModel signatureModel;

  /**
   * Constructs a new SignatureVerificationContext with a given SignatureModel.
   *
   * @param signatureModel The SignatureModel associated with this context.
   */
  public SignatureVerificationContext(SignatureModel signatureModel) {
    this.signatureModel = signatureModel;
  }

  /**
   * Determines whether the export verification results button should be shown.
   *
   * @return true, indicating that the button should always be shown in this context.
   */
  @Override
  public boolean showExportVerificationResultsButton() {
    return true;
  }

  /**
   * Exports the verification results to a CSV file using the SignatureModel's export function.
   *
   * @throws IOException If an I/O error occurs during file writing.
   */
  @Override
  public void exportVerificationResults(int keyIndex) throws IOException {
    if (signatureModel.getNumKeySizesForComparisonMode() > 0) {
      signatureModel.exportVerificationResultsToCSV_ComparisonMode(keyIndex);
    } else {
      signatureModel.exportVerificationResultsToCSV(keyIndex);
    }
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
   * @return A string label describing the benchmarking results for signature verification.
   */
  @Override
  public String getResultsLabel(boolean isComparisonMode) {
    return isComparisonMode ? "Benchmarking Results for Signature Verification ("
        + signatureModel.getSignatureType() + ")"
        : "Benchmarking Results for Signature Verification ("
            + signatureModel.getSignatureType() + "-" + signatureModel.getHashType() + ")";
  }

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
   * Retrieves the number of keys considered as a group in the signature creation benchmarking
   * context. This grouping is relevant for applying different hash functions and parameters during
   * the benchmarking process.
   *
   * @return The number of keys per group used in the benchmarking.
   */
  public int getKeysPerGroup() {
    return signatureModel.getKeysPerGroup();
  }

  /**
   * Provides an array representing the number of trials performed for each key within a group in
   * the context of signature verification benchmarking.
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
   * verification benchmarking.
   *
   * @return The total number of hash functions used in the benchmarking process.
   */
  @Override
  public int getTotalHashFunctions() {
    return signatureModel.getTotalHashFunctions();
  }

  /**
   * Gets the total number of distinct groups formed for the purpose of signature creation
   * benchmarking. Each group represents a unique combination of key configurations or hash
   * functions.
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

