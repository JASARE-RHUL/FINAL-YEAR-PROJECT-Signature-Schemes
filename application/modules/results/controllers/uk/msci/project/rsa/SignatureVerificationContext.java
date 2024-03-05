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
   * Provides a context-specific results label for signature verification benchmarking.
   *
   * @return A string label describing the signature verification benchmarking results.
   */
  @Override
  public String getResultsLabel() {
    return "Benchmarking Results for Signature Verification" + "(" + signatureModel.getSignatureType() + ")" ;
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
}

