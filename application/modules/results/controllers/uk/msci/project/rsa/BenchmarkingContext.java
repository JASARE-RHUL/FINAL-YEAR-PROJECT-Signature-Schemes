package uk.msci.project.rsa;

import java.io.IOException;
import java.util.List;

/**
 * This abstract class that provides a framework for specialised functionality within the results
 * module related to signature operations that have been benchmarked. It offers methods for
 * exporting results and other relevant data, as well as for controlling the display of UI elements
 * in a generalised results view, tailored to the specific signature operation that was
 * benchmarked.
 */
public abstract class BenchmarkingContext {

  /**
   * Exports the batch of public keys generated during the benchmarking process. The method is to be
   * overridden in subclasses to handle operation-specific export logic.
   *
   * @throws IOException If an I/O error occurs during the export.
   */
  public void exportPublicKeyBatch() throws IOException { /* Default empty implementation */ }

  /**
   * Exports the batch of private keys generated during the benchmarking process. The method is to
   * be overridden in subclasses to handle operation-specific export logic.
   *
   * @throws IOException If an I/O error occurs during the export.
   */
  public void exportPrivateKeyBatch() throws IOException { /* Default empty implementation */ }

  /**
   * Exports the batch of signatures generated during the benchmarking process. The method is to be
   * overridden in subclasses to handle operation-specific export logic.
   */
  public void exportSignatureBatch() throws IOException { /* Default empty implementation */ }

  /**
   * Exports the batch of non-recoverable messages generated during the benchmarking process. The
   * method is to be overridden in subclasses to handle operation-specific export logic.
   */
  public void exportNonRecoverableMessages()
      throws IOException { /* Default empty implementation */ }

  /**
   * Exports the results of the signature verification process conducted during benchmarking. The
   * method is to be overridden in subclasses to handle operation-specific export logic.
   */
  public void exportVerificationResults(int keyIndex) throws IOException { /* Default empty implementation */ }


  /**
   * Determines if the UI button for exporting the public key batch should be shown. Subclasses can
   * override this method to provide operation-specific display logic.
   *
   * @return false by default
   */
  public boolean showExportPublicKeyBatchButton() {
    return false;
  }

  /**
   * Determines if the UI button for exporting the private key batch should be shown. Subclasses can
   * override this method to provide operation-specific display logic.
   *
   * @return false by default
   */
  public boolean showExportPrivateKeyBatchButton() {
    return false;
  }

  /**
   * Determines if the UI button for exporting the signature batch should be shown. Subclasses can
   * override this method to provide operation-specific display logic.
   *
   * @return false by default
   */
  public boolean showExportSignatureBatchButton() {
    return false;
  }

  /**
   * Determines if the UI button for exporting verification results should be shown. Subclasses can
   * override this method to provide operation-specific display logic.
   *
   * @return false by default
   */
  public boolean showExportVerificationResultsButton() {
    return false;
  }

  /**
   * Provides the label text for the results view based on the specific signature operation that was
   * benchmarked.
   *
   * @return A string representing the specific label for the benchmarking context.
   */
  public abstract String getResultsLabel();

  /**
   * Determines if the UI button for exporting the non-recoverable portions of messages generated
   * from signature creation should be shown. Subclasses can override this method to provide
   * operation-specific display logic.
   *
   * @return false by default
   */
  public boolean showNonRecoverableBatchButton() {
    return false;
  }


  /**
   * Checks if a list of byte arrays contains any non-empty arrays.
   *
   * @param list The list of byte arrays to check.
   * @return true if at least one byte array in the list is not empty, false otherwise.
   */
  public boolean checkForEmptyLists(List<byte[]> list) {
    if (list != null && !list.isEmpty()) {
      // Check each byte array in the list
      for (byte[] elem : list) {
        // If any byte array is not empty, return true
        if (elem.length > 0) {
          return true;
        }
      }
    }
    // All byte arrays are empty or the list itself is empty/null
    return false;

  }


}
