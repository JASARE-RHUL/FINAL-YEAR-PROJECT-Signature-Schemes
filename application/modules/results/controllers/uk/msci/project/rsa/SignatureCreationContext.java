package uk.msci.project.rsa;

import java.io.IOException;

/**
 * This class is a specialised context for the benchmarking of signature creation operations. It
 * extends BenchmarkingContext to provide functionality specific to signature creation, such as
 * exporting signatures on the generalised results view.
 */
public class SignatureCreationContext extends SignatureBaseContext {

  /**
   * Constructs a SignatureCreationContext with the specified SignatureModel.
   *
   * @param signatureModel The model containing signature creation logic and data.
   */
  public SignatureCreationContext(AbstractSignatureModelBenchmarking signatureModel) {
    super(signatureModel);
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
   * Overrides the method from the base class to provide a specific label for the signature creation
   * operation results. Utilises the base method to construct the label based on the comparison mode
   * status and sets the operation text to "Creation".
   *
   * @param isComparisonMode Indicates whether the operations were conducted in comparison mode.
   * @return A descriptive label for the signature creation operation results.
   */
  @Override
  public String getSignatureResultsLabel(boolean isComparisonMode) {
    return getSignatureResultsLabel(isComparisonMode, "Creation");
  }

}
