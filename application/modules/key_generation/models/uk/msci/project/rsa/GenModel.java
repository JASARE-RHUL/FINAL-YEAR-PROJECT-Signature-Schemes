package uk.msci.project.rsa;


import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.DoubleConsumer;
import javafx.util.Pair;


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
   * A batch of key pairs generated after a benchmarking session for later export
   */
  private List<KeyPair> generatedKeyPairs = new ArrayList<>();


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
      DoubleConsumer progressUpdater) throws InterruptedException {
    try (ExecutorService executor = Executors.newFixedThreadPool(
        Runtime.getRuntime().availableProcessors())) {
      this.keyParams = keyParams;
      int totalWork = numTrials * keyParams.size(); // Total units of work
      final int[] completedWork = {0}; // To keep track of completed work

      for (Pair<int[], Boolean> keyParam : this.keyParams) {
        batchGenerateKeys(executor, numTrials, keyParam, trialProgress -> {
          // Calculate the progress within the current keyParam
          double currentKeyParamProgress = trialProgress / numTrials;

          // Calculate the overall progress including previous keyParams
          double overallProgress =
              ((double) completedWork[0] / totalWork) + (currentKeyParamProgress
                  / keyParams.size());

          progressUpdater.accept(overallProgress);
        });
        completedWork[0] += numTrials; // Update completed work after each keyParam
      }

      // Shutdown the executor service and handle termination.
      executor.shutdown();
      if (!executor.awaitTermination(60, java.util.concurrent.TimeUnit.SECONDS)) {
        System.err.println("Executor did not terminate in the specified time.");
        List<Runnable> droppedTasks = executor.shutdownNow();
        System.err.println("Dropped " + droppedTasks.size() + " tasks.");
      }
    }
  }

  /**
   * Generates a batch of RSA keys for a specific set of key parameters. This method is used within
   * the 'batchGenerateKeys' method for each set of key parameters. It generates RSA keys in
   * parallel using an ExecutorService and updates the progress of the current batch using the given
   * 'progressUpdater' consumer.
   *
   * @param executor        The ExecutorService used for processing of key generation tasks.
   * @param numTrials       The number of trials to be conducted with the given key parameters.
   * @param keyParam        A pair of key parameters, consisting of an array of integers for key
   *                        sizes and a boolean flag for using a smaller 'e' value.
   * @param progressUpdater A DoubleConsumer to report the progress of the current batch
   *                        generation.
   * @throws InterruptedException if the thread executing the batch generation is interrupted.
   */
  public void batchGenerateKeys(ExecutorService executor, int numTrials,
      Pair<int[], Boolean> keyParam,
      DoubleConsumer progressUpdater) throws InterruptedException {

    // Initialise lists to store the time taken for each key generation task.
    List<Long> timesPerKey = new ArrayList<>();

    for (int trial = 0; trial < numTrials; trial++) {
      // List to hold future objects for asynchronous task execution.

      // Submit a new key generation task to the executor service.
      int[] intArray = keyParam.getKey();
      boolean isSmallE = keyParam.getValue();
      GenRSA genRSA = new GenRSA(intArray.length, intArray, isSmallE);
      Future<?> future = executor.submit(() -> {
        genRSA.generateKeyPair();
      });

      // Collect and measure the time taken for each key generation task after submission.
      long startTime = System.nanoTime();
      try {
        future.get(); // Wait for the key generation task to complete.
      } catch (ExecutionException e) {
        throw new RuntimeException(e.getCause());
      }
      long endTime = System.nanoTime() - startTime;
      timesPerKey.add(endTime);

      // Update the progress of the batch process after each trial.
      progressUpdater.accept(trial + 1);
    }

    // Aggregate times from all trials and keys into a single list.
    for (Long keyTime : timesPerKey) {
      clockTimesPerTrial.add(keyTime);
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
   * Generates a batch of keys based on the previously set key parameters.
   *
   * @throws IllegalStateException if key parameters are not set.
   */
  public void generateKeyBatch() {
    if (this.keyParams != null) {
      for (Pair<int[], Boolean> keyParam : this.keyParams) {
        int[] intArray = keyParam.getKey();
        setKeyParameters(intArray.length, intArray);
        setGen(keyParam.getValue());
        generateKey();
        generatedKeyPairs.add(generatedKeyPair);
      }
    } else {
      throw new IllegalStateException(
          "Error. Key batch cannot be generated before a benchmarking session.");
    }
  }

  /**
   * Exports the public keys from the generated key pairs to a batch file.
   *
   * @throws IOException if there is an error during the export process.
   */
  public void exportPublicKeyBatch() throws IOException {
    StringBuilder publicKeyBatch = new StringBuilder();
    for (KeyPair keyPair : generatedKeyPairs) {
      publicKeyBatch.append(keyPair.getPublicKey().getKeyValue()).append("\n");
    }
    FileHandle.exportToFile("batchPublicKey.rsa", publicKeyBatch.toString());
  }

  /**
   * Exports the private keys from the generated key pairs to a batch file.
   *
   * @throws IOException if there is an error during the export process.
   */
  public void exportPrivateKeyBatch() throws IOException {
    StringBuilder privateKeyBatch = new StringBuilder();
    for (KeyPair keyPair : generatedKeyPairs) {
      privateKeyBatch.append(keyPair.getPrivateKey().getKeyValue()).append("\n");
    }
    FileHandle.exportToFile("batchKey.rsa", privateKeyBatch.toString());
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


}
