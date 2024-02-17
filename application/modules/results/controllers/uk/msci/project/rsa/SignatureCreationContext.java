package uk.msci.project.rsa;

import java.io.IOException;

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
}
