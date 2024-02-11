package uk.msci.project.rsa;

import java.io.IOException;

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
   * @throws IOException If an I/O error occurs during the export process.
   */
  public void exportExportVerificationResults() throws IOException {
    signatureModel.exportVerificationResultsToCSV();
  }

  /**
   * Provides a context-specific results label for signature verification benchmarking.
   *
   * @return A string label describing the signature verification benchmarking results.
   */
  @Override
  public String getResultsLabel() {
    return "Benchmarking Results for Signature Verification";
  }
}

