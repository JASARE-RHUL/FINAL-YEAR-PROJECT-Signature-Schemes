package uk.msci.project.rsa;


import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.Consumer;
import java.util.function.DoubleConsumer;
import javafx.util.Pair;
import uk.msci.project.rsa.DisplayUtility;



/**
 * This class is part of the Model component specific to the RSA key generation module in the
 * application, handling the data and logic associated with RSA key generation. This includes
 * maintaining the state of the key generation process, tracking parameters, and managing the
 * execution of key generation in both standard and benchmarking modes. The class provides
 * functionalities for setting up key generation parameters, initiating key generation, exporting
 * generated keys, and conducting batch operations for performance analysis.
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
   * A list that stores the clock times for each trial during batch key generation.
   */
  private List<Long> clockTimesPerTrial = new ArrayList<>();

  /**
   * A list of key parameters for batch key generation trials, where each pair contains key sizes
   * and a flag indicating whether to use a smaller 'e' value in key generation.
   */
  private List<Pair<int[], Boolean>> keyParams;


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
   * Executes a batch of key generation trials in parallel, utilising a thread pool. Each trial
   * involves generating keys based on the provided parameters. Progress of the batch operation is
   * reported through the specified progressUpdater.
   * <p>
   * This method leverages multi-threading to improve performance. The method waits for all trials
   * to complete before returning, ensuring that all results are collected.
   *
   * @param numTrials       The number of key generation trials to run.
   * @param keyParams       A list of pairs, each pair containing key parameters and a flag
   *                        indicating whether to use a smaller 'e' value in key generation. Each
   *                        pair represents the parameters for one key generation trial.
   * @param progressUpdater A DoubleConsumer instance that receives updates on the progress of the
   *                        batch operation, expressed as a double between 0.0 (no progress) and 1.0
   *                        (complete).
   * @throws InterruptedException if the thread executing the method is interrupted while waiting
   *                              for trial results.
   */
  public void batchGenerateKeys(int numTrials, List<Pair<int[], Boolean>> keyParams,
      DoubleConsumer progressUpdater) throws InterruptedException, ExecutionException {
    try (ExecutorService executor = Executors.newFixedThreadPool(
        Runtime.getRuntime().availableProcessors())) {
      this.keyParams = keyParams;

      for (int trial = 0; trial < numTrials; trial++) {
        long startTrialTime = System.nanoTime();

        List<Future<?>> futures = new ArrayList<>();
        for (Pair<int[], Boolean> keyParam : this.keyParams) {
          futures.add(executor.submit(() -> {
            int[] intArray = keyParam.getKey();
            boolean isSmallE = keyParam.getValue();
            GenRSA genRSA = new GenRSA(intArray.length, intArray, isSmallE);
            genRSA.generateKeyPair();
          }));
        }

        // Wait for all tasks of this trial to complete
        for (Future<?> future : futures) {
          future.get(); // Blocks until the task is complete
        }

        clockTimesPerTrial.add(System.nanoTime() - startTrialTime);

        progressUpdater.accept((double) (trial + 1) / numTrials);
      }

      executor.shutdown();
      if (!executor.awaitTermination(60, java.util.concurrent.TimeUnit.SECONDS)) {
        System.err.println("Executor did not terminate in the specified time.");
        List<Runnable> droppedTasks = executor.shutdownNow();
        System.err.println("Dropped " + droppedTasks.size() + " tasks.");
      }
    }
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
   * Exports the batch of generated public and private keys to separate files.
   *
   * @param keyParams a list of key parameters (keySizes and small e option) used to generate the
   *                  keys
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


  /**
   * Gets the list of key parameters for batch key generation trials.
   *
   * @return List of Pair objects, each containing an int array representing key sizes and a boolean
   * flag indicating whether to use a smaller 'e' value.
   */
  public List<Pair<int[], Boolean>> getKeyParams() {
    return keyParams;
  }
}
