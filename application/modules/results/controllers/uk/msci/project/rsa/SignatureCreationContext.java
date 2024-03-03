package uk.msci.project.rsa;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import javafx.util.Pair;

/**
 * This class is a specialised context for the benchmarking of signature creation operations. It
 * extends BenchmarkingContext to provide functionality specific to signature creation, such as
 * exporting signatures on the generalised results view.
 */
public class SignatureCreationContext extends BenchmarkingContext {

  /**
   * The model associated with signature creation that contains logic and data for the operation.
   */
  private SignatureModel signatureModel;

  /**
   * Constructs a SignatureCreationContext with the specified SignatureModel.
   *
   * @param signatureModel The model containing signature creation logic and data.
   */
  public SignatureCreationContext(SignatureModel signatureModel) {
    this.signatureModel = signatureModel;
  }

  /**
   * Exports the batch of signatures generated during signature creation.
   *
   * @throws IOException If an I/O error occurs during file writing.
   */
  @Override
  public void exportSignatureBatch() throws IOException {
    signatureModel.exportSignatureBatch("signatureBatch.rsa");
  }

  /**
   * Exports the batch of non-recoverable messages generated during signature creation.
   *
   * @throws IOException If an I/O error occurs during file writing.
   */
  @Override
  public void exportNonRecoverableMessages() throws IOException {
    signatureModel.exportNonRecoverableBatch("nonRecoverableMessageBatch.txt");
  }

  /**
   * Determines whether the button for exporting non-recoverable message batch should be shown.
   *
   * @return true if there are non-recoverable messages to export, false otherwise.
   */
  @Override
  public boolean showNonRecoverableBatchButton() {
    return checkForEmptyLists(signatureModel.getNonRecoverableMessages());
  }

  /**
   * Indicates whether the export signature batch button should be shown.
   *
   * @return true, as exporting signature batches is applicable in the SignatureCreationContext.
   */
  @Override
  public boolean showExportSignatureBatchButton() {
    return true;
  }

  /**
   * Provides a context-specific results label for signature generation benchmarking.
   *
   * @return A string label describing the benchmarking results for signature generation.
   */
  @Override
  public String getResultsLabel() {
    return "Benchmarking Results for Signature Generation";
  }

  /**
   * Retrieves a map linking each group index to its corresponding list of hash functions and their
   * provable security status.
   *
   * @return A map where each key is a group index and each value is a list of pairs of {@code
   * DigestType} and a boolean indicating if it's provably secure.
   */
  @Override
  public Map<Integer, List<Pair<DigestType, Boolean>>> getKeyConfigToHashFunctionsMap() {
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
   * the context of signature creation benchmarking.
   *
   * @return An array where each element corresponds to the number of trials for a key in a specific
   * group.
   */
  @Override
  public int[] getTrialsPerKeyByGroup() {
    return signatureModel.getTrialsPerKeyByGroup();
  }

  /**
   * Retrieves the total number of hash functions used across all groups in the signature creation
   * benchmarking.
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
