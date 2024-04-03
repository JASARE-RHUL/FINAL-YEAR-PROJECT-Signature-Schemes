package uk.msci.project.rsa;

import java.util.List;
import uk.msci.project.rsa.ResultsModel;

/**
 * Provides utility functions to support the handling and processing of benchmarking results. It is
 * to be used in contexts where results need to be organised or manipulated for display or analysis,
 * such as in the comparison mode of benchmarking.
 */
public class ResultsUtility {

  /**
   * Calculates and returns the length of a key for a given key size index. This method is
   * particularly useful in comparison mode benchmarking, where it helps in determining the key
   * length corresponding to a specific index within a set of results models.
   *
   * @param keySizeIndex                 The index of the key size whose length is to be
   *                                     determined.
   * @param resultsModels                The list of ResultsModel objects containing benchmarking
   *                                     data.
   * @param numKeySizesForComparisonMode The number of key sizes selected for comparison mode.
   * @param keyLengths                   The list of integers representing key lengths.
   * @return The key length corresponding to the specified key size index.
   */
  public static int getKeyLength(int keySizeIndex, List<ResultsModel> resultsModels,
      int numKeySizesForComparisonMode, List<Integer> keyLengths) {
    // Calculate the starting model index for this key size
    int startModelIndex = keySizeIndex * (resultsModels.size() / numKeySizesForComparisonMode);
    int keyLengthsIndex = (int) Math.round(
        ((double) startModelIndex / resultsModels.size()) * keyLengths.size());
    return keyLengths.get(keyLengthsIndex);
  }

}
