package uk.msci.project.rsa;

import java.io.IOException;

/**
 * This abstract class that provides a framework for specialised functionality within the results
 * module related to signature operations that have been benchmarked. It offers methods for exporting
 * results and other relevant data, as well as for controlling the display of UI elements in a
 * generalised results view, tailored to the specific signature operation that was benchmarked.
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
  public void exportSignatureBatch() { /* Default empty implementation */ }

  /**
   * Exports the batch of non-recoverable messages generated during the benchmarking process. The
   * method is to be overridden in subclasses to handle operation-specific export logic.
   */
  public void exportRecoverableMessages() { /* Default empty implementation */ }

  /**
   * Exports the results of the signature verification process conducted during benchmarking. The
   * method is to be overridden in subclasses to handle operation-specific export logic.
   */
  public void exportVerificationResults() { /* Default empty implementation */ }


  /**
   * Determines if the UI button for exporting the public key batch should be shown. Subclasses can
   * override this method to provide operation-specific display logic.
   *
   * @return false by default, indicating the button is not typically shown.
   */
  public boolean showExportPublicKeyBatchButton() {
    return false;
  }

  /**
   * Determines if the UI button for exporting the private key batch should be shown. Subclasses can
   * override this method to provide operation-specific display logic.
   *
   * @return false by default, indicating the button is not typically shown.
   */
  public boolean showExportPrivateKeyBatchButton() {
    return false;
  }

  /**
   * Determines if the UI button for exporting the signature batch should be shown. Subclasses can
   * override this method to provide operation-specific display logic.
   *
   * @return false by default, indicating the button is not typically shown.
   */
  public boolean showExportSignatureBatchButton() {
    return false;
  }

  /**
   * Determines if the UI button for exporting verification results should be shown. Subclasses can
   * override this method to provide operation-specific display logic.
   *
   * @return false by default, indicating the button is not typically shown.
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
}
