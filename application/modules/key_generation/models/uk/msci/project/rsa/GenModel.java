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

  private int numKeySizesForComparisonMode;

  private String publicKeyBatch;

  private String privateKeyBatch;


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
   * Executes batch generation of RSA keys in comparison mode. This mode generates multiple RSA keys
   * for a set of specified key sizes, allowing for comparative analysis (provably secure vs
   * standard) across different configurations. The method generates keys for each configuration,
   * both with standard and smaller 'e' values (provably secure)
   *
   * @param keySizes        A list of integers representing the key sizes for which keys are to be
   *                        generated. Each key size is used to create multiple key configurations.
   * @param numTrials       The number of trials to be conducted for each key configuration. Each
   *                        trial involves generating a key pair with the specified parameters.
   * @param progressUpdater A DoubleConsumer to report the progress of the batch generation process.
   *                        It provides a real-time update on the completion percentage of the
   *                        overall batch generation task.
   */
  public void batchGenerateInComparisonMode(List<Integer> keySizes, int numTrials,
      DoubleConsumer progressUpdater) {
    numKeySizesForComparisonMode = keySizes.size();
    List<Pair<int[], Boolean>> keyParams = new ArrayList<>();
    for (int keySize : keySizes) {
      keyParams.add(new Pair<>(new int[]{keySize / 2, keySize / 2}, false));
      keyParams.add(new Pair<>(new int[]{keySize / 4, keySize / 4, keySize / 2}, false));
      keyParams.add(new Pair<>(new int[]{keySize / 2, keySize / 2}, true));
      keyParams.add(new Pair<>(new int[]{keySize / 4, keySize / 4, keySize / 2}, true));
    }
    batchGenerateKeys(numTrials, keyParams, progressUpdater);


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

  public String getPrivateKeyBatch() {
    return privateKeyBatch;
  }

  public String getPublicKeyBatch() {
    return publicKeyBatch;
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

  public int getNumKeySizesForComparisonMode() {
    return numKeySizesForComparisonMode;
  }
}
