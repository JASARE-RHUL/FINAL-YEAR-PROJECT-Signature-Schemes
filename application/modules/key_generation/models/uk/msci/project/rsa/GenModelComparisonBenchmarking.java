package uk.msci.project.rsa;


import java.util.ArrayList;
import java.util.List;
import java.util.function.DoubleConsumer;
import javafx.util.Pair;


/**
 * This class extends the GenModelBenchmarking class to specialise in comparison benchmarking
 * scenarios. This class is integral for facilitating RSA key generation in scenarios where direct
 * comparisons between different key configurations and parameters are required on a per key size
 * basis. It supports the generation and analysis of keys across various key sizes and
 * configurations. The class is equipped to handle both default key configuration comparisons
 * (standard vs provably secure) and custom-defined key configurations. This includes generating
 * keys based on user-specified key sizes, managing trial runs for performance measurement, and
 * formatting results for both predefined and custom comparison modes.
 */
public class GenModelComparisonBenchmarking extends GenModelBenchmarking {

  /**
   * The number of different key sizes used in comparison benchmarking mode. This field tracks the
   * quantity of distinct key sizes for comparing various sets of key configurations, particularly
   * in standard versus provably secure parameters (default mode) and in user-defined custom
   * configurations (custom mode).
   */
  private int numKeySizesForComparisonMode;


  static final String FIRST_ROW_COMPARISON_MODE = "Standard Parameters (2 Primes (1/2N+1/2N) with arbitrary e selection):";
  static final String SECOND_ROW_COMPARISON_MODE = "Standard Parameters (3 Primes (1/4N+1/4N+1/2N) with arbitrary e selection):";
  static final String THIRD_ROW_COMPARISON_MODE = "Provable Parameters (2 Primes (1/2N+1/2N) with small e selection):";
  static final String FOURTH_ROW_COMPARISON_MODE = "Provable Parameters (3 Primes (1/4N+1/4N+1/2N) with small e selection):";


  /**
   * Constructor for GenModel. This initialises the model which will be bound to the runtime
   * behavior of the signature program. At the point of launch, the model does not have any state
   * until it is initiated by the user.
   */
  public GenModelComparisonBenchmarking() {
  }


  /**
   * Generates a default set of key configurations for comparison mode. This method creates key
   * configurations based on predefined fractions and small e selection settings.
   *
   * @return A list of pairs, each containing an array of integers (representing fractions of key
   * sizes) and a boolean (indicating small e selection).
   */
  public List<Pair<int[], Boolean>> getDefaultKeyConfigurationsData() {

    List<Pair<int[], Boolean>> keyConfigurationsData = new ArrayList<>();

    // Equivalent to keySize / 2, keySize / 2 with small e = false
    keyConfigurationsData.add(new Pair<>(new int[]{1, 2, 1, 2}, false));
    // Equivalent to keySize / 4, keySize / 4, keySize / 2 with small e = false
    keyConfigurationsData.add(new Pair<>(new int[]{1, 4, 1, 4, 1, 2}, false));
    keyConfigurationsData.add(new Pair<>(new int[]{1, 2, 1, 2}, true));
    keyConfigurationsData.add(new Pair<>(new int[]{1, 4, 1, 4, 1, 2}, true));
    return keyConfigurationsData;

  }

  /**
   * Performs batch generation of RSA keys in comparison mode. This method generates keys based on
   * provided key configurations data and sizes. It updates the progress of the batch generation
   * using the provided progress updater.
   *
   * @param keyConfigurationsData The list of key configurations data.
   * @param keySizes              The list of key sizes.
   * @param numTrials             The number of trials to be conducted.
   * @param progressUpdater       A DoubleConsumer to report the progress of batch generation.
   */
  public void batchGenerateKeysInComparisonMode(List<Pair<int[], Boolean>> keyConfigurationsData,
      List<Integer> keySizes, int numTrials,
      DoubleConsumer progressUpdater) {
    numKeySizesForComparisonMode = keySizes.size();
    List<Pair<int[], Boolean>> keyParams = new ArrayList<>();
    for (int keySize : keySizes) {
      for (Pair<int[], Boolean> keyConfig : keyConfigurationsData) {
        int[] fractions = keyConfig.getKey();
        // Each fraction is represented by (numerator, denominator)
        int[] keyParts = new int[fractions.length / 2];

        for (int i = 0; i < fractions.length; i += 2) {
          int numerator = fractions[i];
          int denominator = fractions[i + 1];
          keyParts[i / 2] = (int) Math.round((double) keySize * numerator / denominator);
        }

        keyParams.add(new Pair<>(keyParts, keyConfig.getValue()));
      }
    }
    super.batchGenerateKeys(numTrials, keyParams, progressUpdater);
  }

  /**
   * Formats the custom key configurations into a human-readable string format. Each key
   * configuration is converted into a string describing the number of primes, their fractions, and
   * small e selection.
   *
   * @param keyConfigurationsData The list of key configurations data to format.
   * @return A list of formatted string representations of the key configurations.
   */
  @Override
  public List<String> formatCustomKeyConfigurations(
      List<Pair<int[], Boolean>> keyConfigurationsData) {
    List<String> formattedConfigurations = new ArrayList<>();

    for (Pair<int[], Boolean> keyConfig : keyConfigurationsData) {
      int[] fractions = keyConfig.getKey();
      StringBuilder configString = new StringBuilder();
      int numPrimes = fractions.length / 2;
      configString.append(numPrimes).append(" primes (");

      for (int i = 0; i < fractions.length; i += 2) {
        configString.append(fractions[i]).append("/").append(fractions[i + 1]).append("N");
        if (i < fractions.length - 2) {
          configString.append("+");
        }
      }
      configString.append(")");
      if (Boolean.TRUE.equals(keyConfig.getValue())) {
        configString.append(" with small e");
      }

      formattedConfigurations.add(configString.toString());
    }

    return formattedConfigurations;
  }

  /**
   * Formats the default key configurations for comparison mode into a human-readable string format.
   * This method returns predefined string descriptions for each of the standard comparison modes.
   *
   * @return A list of formatted string representations of the default key configurations for
   * comparison mode.
   */
  @Override
  public List<String> formatDefaultKeyConfigurations() {
    List<String> formattedConfigurations = new ArrayList<>(4);
    formattedConfigurations.add(FIRST_ROW_COMPARISON_MODE);
    formattedConfigurations.add(SECOND_ROW_COMPARISON_MODE);
    formattedConfigurations.add(THIRD_ROW_COMPARISON_MODE);
    formattedConfigurations.add(FOURTH_ROW_COMPARISON_MODE);
    return formattedConfigurations;
  }


  /**
   * Retrieves the number of different key sizes used in comparison benchmarking mode. This count is
   * important for managing comparisons across various key configurations in both default and custom
   * comparison modes. In the default mode, it refers to comparing standard versus provably secure
   * parameters, while in the custom mode, it applies to user-defined configurations.
   *
   * @return The number of different key sizes used in comparison benchmarking mode.
   */
  @Override
  public int getNumKeySizesForComparisonMode() {
    return numKeySizesForComparisonMode;
  }
}
