package uk.msci.project.rsa;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import javafx.util.Pair;

/**
 * A callable task designed for executing a single key generation trial.
 * This task generates RSA keys based on provided parameters and records
 * the time taken for each key generation as well as the total time for the
 * entire batch of keys.
 *
 * This class allows for concurrent execution of multiple key generation
 * trials when used in a multi-threaded environment.
 */
public class KeyGenerationTrialTask implements Callable<List<Long>> {

  /**
   * The key parameters for the trial. Each pair in the list contains an
   * array of integer parameters for key generation and a boolean indicating
   * whether a smaller exponent 'e' is to be used.
   */
  private final List<Pair<int[], Boolean>> keyParams;


  /**
   * Utility for benchmarking the time taken for individual key generations.
   */
  private final BenchmarkingUtility singleKeyBenchmarkingUtil;

  /**
   * Constructs a new KeyGenerationTrialTask with the specified key parameters.
   *
   * @param keyParams The key parameters for the trial, including size and exponent details.
   */
  public KeyGenerationTrialTask(List<Pair<int[], Boolean>> keyParams) {
    this.keyParams = new ArrayList<>(keyParams);
    this.singleKeyBenchmarkingUtil = new BenchmarkingUtility();
  }


  @Override
  public List<Long> call() {
    List<Long> individualKeyTimes = new ArrayList<>();
    for (Pair<int[], Boolean> keyParam : keyParams) {
      int[] intArray = keyParam.getKey();
      boolean isSmallE = keyParam.getValue();
      GenRSA genRSA = new GenRSA(intArray.length, intArray, isSmallE);

      singleKeyBenchmarkingUtil.startTimer();
      genRSA.generateKeyPair();
      singleKeyBenchmarkingUtil.stopTimer();

      individualKeyTimes.add(singleKeyBenchmarkingUtil.getLastComputationTime());
    }
    return individualKeyTimes;
  }
}
