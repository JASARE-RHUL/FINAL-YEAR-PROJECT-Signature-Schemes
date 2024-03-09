package uk.msci.project.rsa;

import java.io.IOException;

/**
 * This class is a specialised context for the benchmarking of signature verification operations. It
 * extends BenchmarkingContext to provide functionality specific to signature verification, such as
 * exporting verification decisions to the generalised results view.
 */
public class SignatureVerificationContext extends SignatureBaseContext {

  /**
   * Constructs a new SignatureVerificationContext with a given SignatureModel.
   *
   * @param signatureModel The SignatureModel associated with this context.
   */
  public SignatureVerificationContext(AbstractSignatureModelBenchmarking signatureModel) {
    super(signatureModel);
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
      signatureModel.exportVerificationResultsToCSV(keyIndex);
  }

  /**
   * Overrides the method from the base class to provide a specific label for the signature
   * verification operation results. Utilises the base method to construct the label based on the
   * comparison mode status and sets the operation text to "Verification".
   *
   * @param isComparisonMode Indicates whether the operations were conducted in comparison mode.
   * @return A descriptive label for the signature verification operation results.
   */
  @Override
  public String getSignatureResultsLabel(boolean isComparisonMode) {
    return getSignatureResultsLabel(isComparisonMode, "Verification");
  }

}

