package uk.msci.project.rsa;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import javafx.stage.Stage;
import uk.msci.project.rsa.HashFunctionSelection;
import uk.msci.project.rsa.DigestType;


/**
 * This abstract class that provides a framework for specialised
 * functionality within the results
 * module related to signature operations that have been benchmarked. It
 * offers methods for
 * exporting results and other relevant data, as well as for controlling the
 * display of UI elements
 * in a generalised results view, tailored to the specific signature
 * operation that was
 * benchmarked.
 */
public abstract class BenchmarkingContext {

  /**
   * Exports the batch of public keys generated during the benchmarking
   * process. The method is to be
   * overridden in subclasses to handle operation-specific export logic.
   *
   * @throws IOException If an I/O error occurs during the export.
   */
  public void exportPublicKeyBatch() throws IOException { /* Default empty
  implementation */ }

  /**
   * Exports the batch of private keys generated during the benchmarking
   * process. The method is to
   * be overridden in subclasses to handle operation-specific export logic.
   *
   * @throws IOException If an I/O error occurs during the export.
   */
  public void exportPrivateKeyBatch() throws IOException { /* Default empty
  implementation */ }

  /**
   * Exports the batch of signatures generated during the benchmarking
   * process. The method is to be
   * overridden in subclasses to handle operation-specific export logic.
   *
   * @throws IOException If an I/O error occurs during file writing.
   */
  public void exportSignatureBatch() throws IOException { /* Default empty
  implementation */ }

  /**
   * Exports the batch of non-recoverable messages generated during the
   * benchmarking process. The
   * method is to be overridden in subclasses to handle operation-specific
   * export logic.
   */
  public void exportNonRecoverableMessages()
    throws IOException { /* Default empty implementation */ }

  /**
   * Exports the results of the signature verification process conducted
   * during benchmarking. The
   * method is intended to be overridden in subclasses to handle
   * operation-specific export logic.
   *
   * @param keyIndex     The index of the verification key.
   * @param keySize      The length of the key/key size for which
   *                     verification results are
   *                     exported.
   * @param primaryStage The primary stage for the UI (JavaFX Stage).
   * @throws IOException If an I/O error occurs during file writing.
   */
  public void exportVerificationResults(int keyIndex, int keySize,
                                        Stage primaryStage)
    throws IOException { /* Default empty implementation */ }


  /**
   * Determines if the UI button for exporting the public key batch should be
   * shown. Subclasses can
   * override this method to provide operation-specific display logic.
   *
   * @return false by default
   */
  public boolean showExportPublicKeyBatchButton() {
    return false;
  }

  /**
   * Determines if the UI button for exporting the private key batch should
   * be shown. Subclasses can
   * override this method to provide operation-specific display logic.
   *
   * @return false by default
   */
  public boolean showExportPrivateKeyBatchButton() {
    return false;
  }

  /**
   * Determines if the UI button for exporting the signature batch should be
   * shown. Subclasses can
   * override this method to provide operation-specific display logic.
   *
   * @return false by default
   */
  public boolean showExportSignatureBatchButton() {
    return false;
  }

  /**
   * Determines if the UI button for exporting verification results should be
   * shown. Subclasses can
   * override this method to provide operation-specific display logic.
   *
   * @return false by default
   */
  public boolean showExportVerificationResultsButton() {
    return false;
  }

  /**
   * Provides a context-specific label for the results view based on the
   * specific operation that was
   * benchmarked. This label is used to display relevant information about
   * the benchmarking context
   * in the UI, offering users a clear understanding of the results being
   * presented. The label can
   * vary depending on whether the benchmarking is conducted in normal
   * benchmarking mode displaying
   * the single hash function used, differing from comparison mode where
   * multiple hash functions can
   * potentially be used so the hash function name is omitted from label.
   *
   * @param isComparisonMode A boolean flag indicating whether the
   *                         benchmarking is done in
   *                         comparison mode, which may affect the label
   *                         content.
   * @return A string representing the specific label for the benchmarking
   * context.
   */
  public abstract String getResultsLabel(boolean isComparisonMode);


  /**
   * Determines if the UI button for exporting the non-recoverable portions
   * of messages generated
   * from signature creation should be shown. Subclasses can override this
   * method to provide
   * operation-specific display logic.
   *
   * @return false by default
   */
  public boolean showNonRecoverableBatchButton() {
    return false;
  }


  /**
   * Retrieves a map linking each group index to its corresponding list of
   * hash functions and their
   * provable security status. This abstract method provides a framework for
   * subclasses to implement
   * specific logic related to hash function configurations in different
   * benchmarking contexts.
   *
   * @return A map where each key is a group index and each value is a list
   * of pairs of {@code
   * DigestType} and a boolean indicating if it's provably secure. Returns
   * null in the default
   * implementation.
   */
  public Map<Integer, List<HashFunctionSelection>> getKeyConfigToHashFunctionsMap() {
    return null;
  }

  /**
   * Retrieves the number of keys considered as a group in the benchmarking
   * context.
   *
   * @return The number of keys per group used in the benchmarking. Returns 0
   * in the default
   * implementation.
   */
  public int getKeysPerGroup() {
    return 0;
  }

  /**
   * Provides an array representing the number of trials performed for each
   * key within a group in a
   * benchmarking context.
   *
   * @return An array where each element corresponds to the number of trials
   * for a key in a specific
   * group. Returns null in the default implementation.
   */
  public int[] getTrialsPerKeyByGroup() {
    return null;
  }

  /**
   * Retrieves the total number of hash functions used across all groups in
   * the benchmarking
   * context.
   *
   * @return The total number of hash functions used in the benchmarking
   * process. Returns 0 in the
   * default implementation.
   */
  public int getTotalHashFunctions() {
    return 0;
  }

  /**
   * Retrieves the total number of distinct groups formed in a benchmarking
   * context.
   *
   * @return The total number of groups in the benchmarking process. Returns
   * 0 in the default
   * implementation.
   */
  public int getTotalGroups() {
    return 0;
  }

  /**
   * Retrieves the fraction used to calculate the custom hash size based on
   * provided key lengths in
   * normal benchmarking mode.
   *
   * @return corresponding fraction represented as an int list
   */
  public int[] getCustomHashSizeFraction() {
    return null;
  }

  /**
   * Retrieves the type of hash function currently set in the model.
   *
   * @return The current hash function type.
   */
  public DigestType getHashType() {
    return null;
  }

  /**
   * Indicates whether the signature scheme operates in provably secure mode.
   *
   * @return {@code true} if the signature scheme is operating in provably
   * secure mode, {@code
   * false} otherwise.
   */
  public boolean getProvablySecure() {
    return false;
  }


}
