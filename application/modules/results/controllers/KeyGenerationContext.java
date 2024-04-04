package uk.msci.project.rsa;

import java.io.IOException;

import uk.msci.project.rsa.BenchmarkingContext;
import uk.msci.project.rsa.GenModelBenchmarking;


/**
 * This class is a specialised context for the benchmarking of key generation
 * operations. It extends
 * BenchmarkingContext to provide functionality specific to key generation,
 * such as exporting
 * generated public and private key batches on generalised results view.
 */
public class KeyGenerationContext extends BenchmarkingContext {

  /**
   * Model handling the generation of keys.
   */
  private GenModelBenchmarking genModel;

  /**
   * Constructs a KeyGenerationContext with a specified GenModel. Initializes
   * the key generation
   * process.
   *
   * @param genModel The GenModel instance responsible for key generation.
   */
  public KeyGenerationContext(GenModelBenchmarking genModel) {
    this.genModel = genModel;
  }

  /**
   * Exports the batch of public keys generated during the benchmarking
   * process. Delegates the
   * operation to the GenModel.
   *
   * @throws IOException If an I/O error occurs during the export.
   */
  @Override
  public void exportPublicKeyBatch() throws IOException {
    genModel.exportPublicKeyBatch();
  }

  /**
   * Exports the batch of private keys generated during the benchmarking
   * process. Delegates the
   * operation to the GenModel.
   *
   * @throws IOException If an I/O error occurs during the export.
   */
  @Override
  public void exportPrivateKeyBatch() throws IOException {
    genModel.exportPrivateKeyBatch();
  }

  /**
   * Indicates whether the export public key batch button should be shown.
   * Always returns true for
   * KeyGenerationContext.
   *
   * @return true, indicating the button should be shown.
   */
  @Override
  public boolean showExportPublicKeyBatchButton() {
    return true;
  }

  /**
   * Indicates whether the export private key batch button should be shown.
   * Always returns true for
   * KeyGenerationContext.
   *
   * @return true, indicating the button should be shown.
   */
  @Override
  public boolean showExportPrivateKeyBatchButton() {
    return true;
  }

  /**
   * Provides a context-specific results label for key generation benchmarking.
   *
   * @return A string label describing the key generation benchmarking results.
   */
  /**
   * Provides a context-specific label for the results view based on the
   * specific signature
   * operation that was benchmarked. This label is used to display relevant
   * information about the
   * benchmarking context in the UI, offering users a clear understanding of
   * the results being
   * presented.
   *
   * @param isComparisonMode A boolean flag indicating whether the benchmarking.
   * @return A string label describing the key generation benchmarking results.
   */
  @Override
  public String getResultsLabel(boolean isComparisonMode) {
    return "Benchmarking Results for Key Generation";
  }
}
