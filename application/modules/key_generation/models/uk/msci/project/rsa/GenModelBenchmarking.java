package uk.msci.project.rsa;


import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.DoubleConsumer;
import javafx.util.Pair;


/**
 * This class, extending GenModel, is specifically designed for RSA key generation in benchmarking
 * mode. It facilitates the batch generation of RSA keys, supporting performance analysis and
 * comparisons between different key configurations and parameters. It is limited to standard
 * benchmarking scenarios and does not support comparison benchmarking, presenting results for
 * multiple key configurations side-by-side.
 */

public class GenModelBenchmarking extends GenModel {


  /**
   * A list that stores the clock times for each trial during batch key generation.
   */
  List<Long> clockTimesPerTrial = new ArrayList<>();

  /**
   * A list of key parameters for batch key generation trials, where each pair contains key sizes
   * and a flag indicating whether to use a smaller 'e' value in key generation.
   */
  List<Pair<int[], Boolean>> keyParams;


  /**
   * A String representing a batch of public keys. These keys are typically used in signature
   * verification processes within the benchmarking mode. The batch facilitates comparisons and
   * analysis across different key configurations and parameters.
   */
  String publicKeyBatch;

  /**
   * A String representing a batch of private keys. These keys are primarily used in the signature
   * creation process during benchmarking mode. The batch enables efficient handling of multiple
   * keys for performance analysis and comparative evaluations of different key configurations.
   */
  String privateKeyBatch;


  /**
   * Constructor for GenModel. This initialises the model which will be bound to the runtime
   * behavior of the signature program. At the point of launch, the model does not have any state
   * until it is initiated by the user.
   */
  public GenModelBenchmarking() {
  }


  /**
   * Performs batch generation of RSA keys. This method allows for multiple trials of key generation
   * using different key parameters specified in the 'keyParams' list. Each trial involves
   * generating keys with the specified parameters and measuring the time taken for each generation.
   * The method updates the progress of batch generation using the provided 'progressUpdater'
   * consumer.
   *
   * @param numTrials       The number of trials to be conducted for each set of key parameters.
   * @param keyParams       A list of key parameters, where each item is a pair consisting of an
   *                        array of integers representing key sizes and a boolean flag indicating
   *                        whether to use a smaller 'e' value in key generation.
   * @param progressUpdater A DoubleConsumer to report the progress of the batch generation
   *                        process.
   * @throws InterruptedException if the thread executing the batch generation is interrupted.
   */
  public void batchGenerateKeys(int numTrials, List<Pair<int[], Boolean>> keyParams,
      DoubleConsumer progressUpdater) {
    clockTimesPerTrial.clear();
    this.keyParams = keyParams;
    int totalWork = numTrials * keyParams.size(); // Total units of work
    final int[] completedWork = {0}; // To keep track of completed work

    for (Pair<int[], Boolean> keyParam : this.keyParams) {
      batchGenerateKeys(numTrials, keyParam, trialProgress -> {
        // Increment the completed work with each trial
        completedWork[0]++;

        // Calculate the overall progress
        double overallProgress = (double) completedWork[0] / totalWork;
        progressUpdater.accept(overallProgress);
      });
    }
  }

  /**
   * Performs batch generation of RSA keys with specified parameters for a single key configuration.
   * This method generates keys with the specified parameters and measures the time taken for each
   * generation for a fixed number of trials.
   *
   * @param numTrials       The number of trials to be conducted for the specified key parameters.
   * @param keyParam        A pair consisting of an array of integers representing key sizes and a
   *                        boolean flag indicating whether to use a smaller 'e' value in key
   *                        generation.
   * @param progressUpdater A DoubleConsumer to report the progress of the batch generation
   *                        process.
   */
  public void batchGenerateKeys(int numTrials, Pair<int[], Boolean> keyParam,
      DoubleConsumer progressUpdater) {
    List<Long> timesPerKey = new ArrayList<>();

    for (int trial = 0; trial < numTrials; trial++) {
      int[] intArray = keyParam.getKey();
      boolean isSmallE = keyParam.getValue();
      GenRSA genRSA = new GenRSA(intArray.length, intArray, isSmallE);

      long startTime = System.nanoTime();
      genRSA.generateKeyPair();
      long endTime = System.nanoTime() - startTime;

      timesPerKey.add(endTime);
      progressUpdater.accept((double) (trial + 1) / numTrials);
    }

    // Aggregate times from all trials and keys into a single list.
    clockTimesPerTrial.addAll(timesPerKey);

  }

  /**
   * Gets the list of clock times for each trial during batch key generation.
   *
   * @return List of Long values representing the clock times for each trial.
   */
  public List<Long> getClockTimesPerTrial() {
    return clockTimesPerTrial;
  }


  /**
   * Generates a batch of keys based on the previously set key parameters.
   *
   * @throws IllegalStateException if key parameters are not set.
   */
  public boolean generateKeyBatch() {
    boolean isProvablySecureKeyBatch = true;
    StringBuilder publicKeyBatchBuilder = new StringBuilder();
    StringBuilder privateKeyBatchBuilder = new StringBuilder();
    if (this.keyParams != null) {
      for (Pair<int[], Boolean> keyParam : this.keyParams) {
        int[] intArray = keyParam.getKey();
        setKeyParameters(intArray.length, intArray);
        boolean isSmallE = keyParam.getValue();
        isProvablySecureKeyBatch = isSmallE && isProvablySecureKeyBatch;
        setGen(isSmallE);
        generateKey();
        publicKeyBatchBuilder.append(generatedKeyPair.getPublicKey().getKeyValue()).append("\n");
        privateKeyBatchBuilder.append(generatedKeyPair.getPrivateKey().getKeyValue()).append("\n");
      }
      this.publicKeyBatch = publicKeyBatchBuilder.toString();
      this.privateKeyBatch = privateKeyBatchBuilder.toString();
    } else {
      throw new IllegalStateException(
          "Error. Key batch cannot be generated before a benchmarking session.");
    }
    return isProvablySecureKeyBatch;
  }

  /**
   * Exports the public keys from the generated key pairs to a batch file.
   *
   * @throws IOException if there is an error during the export process.
   */
  public void exportPublicKeyBatch() throws IOException {
    FileHandle.exportToFile("batchPublicKey.rsa", publicKeyBatch);
  }


  /**
   * Exports the private keys from the generated key pairs to a batch file.
   *
   * @throws IOException if there is an error during the export process.
   */
  public void exportPrivateKeyBatch() throws IOException {
    FileHandle.exportToFile("batchKey.rsa", privateKeyBatch);
  }


  /**
   * Gets the list of key parameters for batch key generation trials.
   *
   * @return List of Pair objects, each containing an int array representing key sizes and a boolean
   * flag indicating whether to use a smaller 'e' value.
   */
  public List<Pair<int[], Boolean>> getKeyParams() {
    return keyParams;
  }

  /**
   * Retrieves the batch of private keys generated for use in benchmarking mode.
   *
   * @return A String representing the batch of private keys.
   */
  public String getPrivateKeyBatch() {
    return privateKeyBatch;
  }

  /**
   * Retrieves the batch of public keys generated for use in benchmarking mode. The public keys are
   * used in signature verification processes.
   *
   * @return A String representing the batch of public keys.
   */
  public String getPublicKeyBatch() {
    return publicKeyBatch;
  }


  /**
   * Sums the key sizes for each configuration within a provided list of key parameter pairs.
   *
   * @param pairs A List of Pair objects representing key configurations.
   * @return A List of Integer values representing the total key sizes for each configuration.
   */
  public List<Integer> summedKeySizes(List<Pair<int[], Boolean>> pairs) {
    List<Integer> summedArrays = new ArrayList<>();

    for (Pair<int[], Boolean> pair : pairs) {

      int[] array = pair.getKey();
      int sum = 0;
      for (int num : array) {
        sum += num;
      }
      summedArrays.add(sum); // Add the sum as a single-element array

    }
    return summedArrays;
  }


  /**
   * Formats custom key configurations into a human-readable string format. This method is not
   * supported in the standard benchmarking mode, as custom key configurations are specific to the
   * comparison benchmarking mode.
   *
   * @param keyConfigurationsData The list of key configurations data to format.
   * @return A list of formatted string representations of the key configurations.
   * @throws UnsupportedOperationException If called in standard benchmarking mode.
   */
  public List<String> formatCustomKeyConfigurations(
      List<Pair<int[], Boolean>> keyConfigurationsData) {
    throw new UnsupportedOperationException(
        "formatCustomKeyConfigurations is not supported in standard benchmarking mode");
  }

  /**
   * Formats default key configurations for comparison mode into a human-readable string format.
   * This method is not supported in the standard benchmarking mode, as default key configurations
   * are exclusive to comparison benchmarking mode.
   *
   * @return A list of formatted string representations of the default key configurations.
   * @throws UnsupportedOperationException If called in standard benchmarking mode.
   */
  public List<String> formatDefaultKeyConfigurations() {
    throw new UnsupportedOperationException(
        "formatDefaultKeyConfigurations is not supported in standard benchmarking mode");
  }

  /**
   * Retrieves the number of different key sizes used in comparison benchmarking mode. This method
   * is not applicable in the standard benchmarking mode and is exclusive to comparison benchmarking
   * mode.
   *
   * @return The number of different key sizes used in comparison benchmarking mode.
   * @throws UnsupportedOperationException If called in standard benchmarking mode.
   */
  public int getNumKeySizesForComparisonMode() {
    throw new UnsupportedOperationException(
        "getNumKeySizesForComparisonMode is not supported in standard benchmarking mode");
  }

  /**
   * Generates a default set of key configurations for comparison mode. This method is not supported
   * in the standard benchmarking mode, as it pertains exclusively to comparison benchmarking mode
   * where predefined configurations are used for comparison.
   *
   * @return A list of pairs, each containing an array of integers (representing fractions of key
   * sizes) and a boolean (indicating small e selection).
   * @throws UnsupportedOperationException If called in standard benchmarking mode.
   */
  public List<Pair<int[], Boolean>> getDefaultKeyConfigurationsData() {
    throw new UnsupportedOperationException(
        "getDefaultKeyConfigurationsData is not supported in standard benchmarking mode");
  }


}
