package uk.msci.project.rsa;


import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.Consumer;
import javafx.util.Pair;

/**
 * This class is part of the Model component specific to the RSA key generation process. It
 * encapsulates the data and the logic required to keep track of a user initiated key generation
 * process in standard and benchmarking modes.
 */
public class GenModel {

  /**
   * The number of prime factors to be used in modulus generation.
   */
  private int k;

  /**
   * An array representing the bit size for each prime factor.
   */
  private int[] lambda;

  /**
   * The current state of the model representing a tracked instance of GenRSA
   */
  private GenRSA currentGen;

  /**
   * The Key pair corresponding to the current Key Generation instance
   */
  private KeyPair generatedKeyPair;

  /**
   * Stores all individual key generation times from each trial.
   */
  private List<List<Long>> allIndividualKeyTimes = new ArrayList<>();
  /**
   * Stores the total time taken for each batch of key generations from each trial.
   */
  private List<Long> allBatchTimes = new ArrayList<>();


  /**
   * Constructor for GenModel. This initialises the model which will be bound to the runtime
   * behavior of the signature program. At the point of launch, the model does not have any state
   * until it is initiated by the user.
   */
  public GenModel() {
  }

  /**
   * Sets the key parameters for RSA key generation.
   *
   * @param k      The number of prime factors in the modulus.
   * @param lambda An array of integers representing the bit sizes for each prime factor.
   */
  public void setKeyParameters(int k, int[] lambda) {
    this.k = k;
    this.lambda = lambda;
  }


  /**
   * Initialises the state of the RSA key generation process. This method sets up the current
   * generation process with the specified parameters for the number of primes and their bit
   * lengths. It also allows for the option to use a smaller exponent 'e' in the RSA key
   * generation.
   *
   * @param isSmallE A boolean flag indicating whether a smaller 'e' should be used in the
   *                 generation process. If true, a smaller 'e' is used. If false, a standard size
   *                 'e' is used.
   */
  public void setGen(boolean isSmallE) {
    this.currentGen = isSmallE ? new GenRSA(k, lambda, true) : new GenRSA(k, lambda);
  }


  /**
   * Generates an RSA key with using the currently tracked generation process.
   *
   * @throws IllegalStateException if key parameters are not set before key generation.
   */
  public void generateKey() {
    if (currentGen == null) {
      throw new IllegalStateException("Key Size needs to be set before a key can be generated");
    }
    generatedKeyPair = currentGen.generateKeyPair();
  }

  /**
   * Gets the freshly generated key pair
   *
   * @return KeyPair representing the generated public and private key
   */
  public KeyPair getGeneratedKeyPair() {
    KeyPair keyPair = generatedKeyPair;
    return keyPair;
  }

  /**
   * Exports the generated RSA key pair to respective files.
   *
   * @throws IOException           if there is an error during the export process.
   * @throws IllegalStateException if no key has been generated yet.
   */
  public void export() throws IOException {
    if (generatedKeyPair == null) {
      throw new IllegalStateException("No key has been generated yet.");
    }
    generatedKeyPair.getPrivateKey().exportKey("key.rsa");
    generatedKeyPair.getPublicKey().exportKey("publicKey.rsa");
  }

  /**
   * Executes a multiple key generation trials in parallel, utilising a thread pool. Each trial
   * involves generating a batch of keys based on the provided parameters for each. Progress of the
   * batch operation is reported through the specified progressUpdater.
   * <p>
   * This method leverages multi-threading to improve performance. The method waits for all trials
   * to complete before returning, ensuring that all results are collected.
   *
   * @param numTrials       The number of key generation trials to run.
   * @param keyParams       A list of pairs, each pair containing key parameters and a flag
   *                        indicating whether to use a smaller 'e' value in key generation. Each
   *                        pair represents the parameters for one key generation trial.
   * @param progressUpdater A Consumer<Double> instance that receives updates on the progress of the
   *                        batch operation, expressed as a double between 0.0 (no progress) and 1.0
   *                        (complete).
   * @throws InterruptedException if the thread executing the method is interrupted while waiting
   *                              for trial results.
   */
  public void batchGenerateKeys(int numTrials, List<Pair<int[], Boolean>> keyParams,
      Consumer<Double> progressUpdater) throws InterruptedException {
    try (ExecutorService executor = Executors.newFixedThreadPool(
        Runtime.getRuntime().availableProcessors())) {
      List<Future<TrialResult>> futures = new ArrayList<>();

      // Submit tasks to the executor service
      for (int i = 0; i < numTrials; i++) {
        KeyGenerationTrialTask task = new KeyGenerationTrialTask(keyParams);
        futures.add(executor.submit(task));
      }

      executor.shutdown();

      // Collect results from the futures
      for (int i = 0; i < futures.size(); i++) {
        try {
          TrialResult result = futures.get(i).get();
          allIndividualKeyTimes.add(result.getIndividualKeyTimes());
          allBatchTimes.add(result.getBatchTime());
          progressUpdater.accept((i + 1) / (double) numTrials);
        } catch (ExecutionException e) {
          e.printStackTrace();
        }
      }

      executor.awaitTermination(Long.MAX_VALUE, java.util.concurrent.TimeUnit.NANOSECONDS);
    }
  }

  /**
   * Exports the batch of generated public and private keys to separate files.
   *
   * @param keyParams  a list of key parameters (keySizes and small e option) used to generate the keys
   * @throws IOException if an I/O error occurs
   */
  public void exportKeyBatch(List<Pair<int[], Boolean>> keyParams) throws IOException {
    StringBuilder publicKeyBatch = new StringBuilder();
    StringBuilder privateKeyBatch = new StringBuilder();

    for (Pair<int[], Boolean> keyParam : keyParams) {
      int[] intArray = keyParam.getKey();
      setKeyParameters(intArray.length, intArray);
      setGen(keyParam.getValue());
      generateKey();

      publicKeyBatch.append(generatedKeyPair.getPublicKey().getKeyValue()).append("\n");
      privateKeyBatch.append(generatedKeyPair.getPrivateKey().getKeyValue()).append("\n");
    }
    FileHandle.exportToFile("batchKey.rsa", privateKeyBatch.toString());
    FileHandle.exportToFile("batchPublicKey.rsa", publicKeyBatch.toString());
  }


}
