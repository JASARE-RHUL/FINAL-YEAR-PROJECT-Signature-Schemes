package uk.msci.project.rsa;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.DoubleConsumer;
import java.util.stream.Collectors;
import java.util.zip.DataFormatException;
import javafx.util.Pair;
import net.sf.saxon.expr.instruct.Message;
import uk.msci.project.rsa.exceptions.InvalidDigestException;
import uk.msci.project.rsa.exceptions.InvalidSignatureTypeException;

/**
 * This class is part of the Model component specific to digital signature operations providing
 * methods to sign data and verify signatures.  It encapsulates the data and the logic required to
 * keep track of a user initiated digital signature scheme.
 */
public class SignatureModel {

  /**
   * The current state of the model representing a tracked instance of a signature scheme
   */
  private SigScheme currentSignatureScheme;
  /**
   * The Key corresponding to the current Signature Scheme instance
   */
  private Key key;

  /**
   * The type of to the current Signature Scheme instance
   */
  private SignatureType currentType;

  /**
   * The type of hash function used in the signature scheme.
   */
  private DigestType currentHashType = DigestType.SHA_256;

  /**
   * The size of the hash output in bytes.
   */
  private int hashSize;

  /**
   * Indicator of whether the current signature scheme operates in provably secure mode.
   */
  private boolean isProvablySecure;

  /**
   * A list that stores the clock times for each trial during batch signature generation. This is
   * useful for benchmarking the performance of the signature creation process.
   */
  private List<Long> clockTimesPerTrial = new ArrayList<>();

  /**
   * A list to store the generated signatures from the benchmarking process. Each entry corresponds
   * to a signature generated for a message in the batch.
   */
  private List<byte[]> signaturesFromBenchmark = new ArrayList<>();

  /**
   * A list to store the non-recoverable part of the messages from the signature generation process.
   * This is relevant for signature schemes that involve message recovery.
   */
  private List<byte[]> nonRecoverableMessages = new ArrayList<>();

  /**
   * Stores the recoverable parts of messages from the verification process. This list is relevant
   * for signature schemes that involve message recovery.
   */
  private List<byte[]> recoverableMessages = new ArrayList<>();


  /**
   * Stores the results of the verification process. Each boolean value in this list represents the
   * outcome of a verification trial.
   */
  private List<Boolean> verificationResults = new ArrayList<>();


  /**
   * A batch of private keys used for generating signatures in a benchmarking session.
   */
  private List<PrivateKey> privKeyBatch = new ArrayList<PrivateKey>();

  /**
   * A batch of public keys corresponding to the private keys.
   */
  private List<PublicKey> publicKeyBatch = new ArrayList<PublicKey>();

  /**
   * The number of trials to run in the benchmarking/batch methods. This determines how many
   * messages from the batch file are processed.
   */
  private int numTrials = 0;

  /**
   * The message file to be processed during benchmarking.
   */
  private File messageFile;

  /**
   * Constructs a new {@code SignatureModel} without requiring an initial key representative of the
   * fact that at program launch, the model does not have any state: until it is initiated by the
   * user
   */
  public SignatureModel() {
  }

  /**
   * Sets the type of signature to be used.
   *
   * @param signatureType The type of signature to be set.
   */
  public void setSignatureType(SignatureType signatureType) {
    this.currentType = signatureType;
  }

  /**
   * Returns the current type of signature set in the model.
   *
   * @return The current type of signature.
   */
  public SignatureType getSignatureType() {
    return currentType;
  }

  /**
   * Sets the type of hash function to be used.
   *
   * @param hashType The type of hash function to be set.
   */
  public void setHashType(DigestType hashType) {
    this.currentHashType = hashType;
  }

  /**
   * Retrieves the type of hash function currently set in the model.
   *
   * @return The current hash function type.
   */
  public DigestType getHashType() {
    return currentHashType;
  }

  /**
   * Sets the size of the hash output in bytes.
   *
   * @param hashSize The size of the hash output in bytes to be set.
   * @throws IllegalArgumentException if the hash size is negative.
   */
  public void setHashSize(int hashSize) {
    if (hashSize < 0) {
      throw new IllegalArgumentException(
          "Hash size must be a non-negative integer");
    }
    this.hashSize = hashSize;
  }


  /**
   * Retrieves the size of the hash output in bits.
   *
   * @return The size of the hash output in bits.
   */
  public int getHashSize() {
    return hashSize;
  }


  /**
   * Sets the key to be used in the signature scheme.
   *
   * @param key The key to be set for the signature operations.
   */
  public void setKey(Key key) {
    this.key = key;
  }

  /**
   * Returns the key for corresponding to current signature scheme.
   *
   * @return The Key respective to the currently set signature scheme.
   */
  public Key getKey() {
    return key;
  }

  /**
   * Clears all private keys from the private key batch.
   */
  public void clearPrivateKeyBatch() {
    privKeyBatch.clear();
  }

  /**
   * Clears all public keys from the public key batch.
   */
  public void clearPublicKeyBatch() {
    publicKeyBatch.clear();
  }


  /**
   * Instantiates a signature scheme based on the current key and signature type. Throws an
   * exception if either the key or the signature type is not set.
   *
   * @throws InvalidSignatureTypeException if the parameter passed SignatureType is not valid or
   *                                       supported.
   */
  public void instantiateSignatureScheme()
      throws InvalidSignatureTypeException, NoSuchAlgorithmException, InvalidDigestException, NoSuchProviderException {
    if (key != null && currentType != null) {
      currentSignatureScheme = SignatureFactory.getSignatureScheme(currentType, key,
          isProvablySecure);
      try {
        currentSignatureScheme.setDigest(currentHashType, hashSize);
      } catch (IllegalArgumentException e) {
        throw new IllegalArgumentException(
            "Custom hash size must a positive integer that allows the minimum bytes of padding to be incorporated");
      }

    } else {
      throw new IllegalStateException(
          "Both key and signature type need to be set before instantiating a signature scheme");
    }
  }

  /**
   * Signs the given data using the current signature scheme.
   *
   * @param data The data to be signed.
   * @return A byte array representing the digital signature.
   * @throws IllegalStateException if the key or signature type is not set before signing.
   * @throws DataFormatException   If signing process fails due to incorrect format.
   */
  public byte[] sign(byte[] data) throws DataFormatException {
    if (currentSignatureScheme == null) {
      throw new IllegalStateException("Both key and signature type need to be set before signing");
    }
    return currentSignatureScheme.sign(data);
  }

  /**
   * Verifies a signature against the provided data using the current signature scheme.
   *
   * @param data      The data to be verified against the signature.
   * @param signature The signature to be verified.
   * @return {@code true} if the signature is valid, {@code false} otherwise.
   * @throws IllegalStateException if the key or signature type is not set before verification.
   * @throws DataFormatException   If verification fails due to incorrect format.
   */
  public boolean verify(byte[] data, byte[] signature) throws DataFormatException {
    if (currentSignatureScheme == null) {
      throw new IllegalStateException(
          "Both key and signature type need to be set before verification");
    }
    return currentSignatureScheme.verify(data, signature);
  }

  /**
   * Gets the non-recoverable portion of message as generated by the adjusted sign method for
   * signature schemes with message recovery
   *
   * @return signing process initialised non-recoverable portion of message
   */
  public byte[] getNonRecoverableM() {
    return currentSignatureScheme.getNonRecoverableM();
  }

  /**
   * Gets recoverable portion of message as generated by the adjusted verify method for signature
   * schemes with message recovery
   *
   * @return verification process initialised non-recoverable portion of message
   */
  public byte[] getRecoverableM() {
    return currentSignatureScheme.getRecoverableM();
  }

  /**
   * Sets the number of trials to be performed in the benchmarking of the signature creation
   * process.
   *
   * @param numTrials The number of trials to be set.
   */
  public void setNumTrials(int numTrials) {
    this.numTrials = numTrials;
  }

  /**
   * Retrieves the number of trials set for the benchmarking of the signature creation process. This
   * value indicates how many messages from the batch file will be processed.
   *
   * @return The number of trials currently set for signature generation.
   */
  public int getNumTrials() {
    return numTrials;
  }

  /**
   * Adds a new private key to the batch of private keys used for signature generation. The key is
   * created from the provided string representation and then added to the batch.
   *
   * @param keyValue The string representation of the private key to be added to the batch.
   */
  public void addPrivKeyToBatch(String keyValue) {
    privKeyBatch.add(new PrivateKey(keyValue));
  }

  /**
   * Adds a new public key to the batch of public keys, corresponding to the private keys used for
   * signature generation. The key is created from the provided string representation and then added
   * to the batch.
   *
   * @param keyValue The string representation of the public key to be added to the batch.
   */
  public void addPublicKeyToBatch(String keyValue) {
    publicKeyBatch.add(new PublicKey(keyValue));
  }

  /**
   * Retrieves the number of public keys in the public key batch.
   *
   * @return The size of the public key batch.
   */
  public int getPublicKeyBatchLength() {
    return publicKeyBatch.size();
  }

  /**
   * Retrieves the number of private keys in the private key batch.
   *
   * @return The size of the private key batch.
   */
  public int getPrivateKeyBatchLength() {
    return privKeyBatch.size();
  }

  /**
   * Processes a batch of messages to create digital signatures using the private keys in the
   * batch.The method also updates the progress of the batch signing process using the provided
   * progressUpdater consumer.
   *
   * @param batchMessageFile The file containing the messages to be signed in the batch process.
   * @param progressUpdater  A consumer to update the progress of the batch signing process.
   * @throws InterruptedException If the thread executing the batch creation is interrupted.
   */

  public void batchCreateSignatures(File batchMessageFile, DoubleConsumer progressUpdater)
      throws InterruptedException {
    try (ExecutorService executor = Executors.newFixedThreadPool(
        Runtime.getRuntime().availableProcessors())) {
      try (BufferedReader messageReader = new BufferedReader(new FileReader(batchMessageFile))) {
        // Initialise lists to store times and results (signatures and non-recoverable parts) for each key.
        List<List<Long>> timesPerKey = new ArrayList<>();
        List<List<byte[]>> signaturesPerKey = new ArrayList<>();
        List<List<byte[]>> nonRecoverableMessagesPerKey = new ArrayList<>();

        for (int k = 0; k < privKeyBatch.size(); k++) {
          timesPerKey.add(new ArrayList<>());
          signaturesPerKey.add(new ArrayList<>());
          nonRecoverableMessagesPerKey.add(new ArrayList<>());
        }

        String message;
        int totalWork = numTrials * privKeyBatch.size();
        int completedWork = 0;
        int messageCounter = 0;
        while ((message = messageReader.readLine()) != null && messageCounter < this.numTrials) {
          int keyIndex = 0;
          for (PrivateKey key : privKeyBatch) {
            int finalCompletedWork = completedWork;
            batchCreateSignatures(executor, messageCounter, message, keyIndex, key,
                trialProgress -> {
                  double currentKeyProgress = trialProgress / numTrials;
                  double overallProgress =
                      ((double) finalCompletedWork / totalWork) + (currentKeyProgress
                          / privKeyBatch.size());
                  progressUpdater.accept(overallProgress);
                }, timesPerKey, signaturesPerKey,
                nonRecoverableMessagesPerKey);
            completedWork++;
            keyIndex++;
          }
          messageCounter++;

        }
        shutdownExecutorService(executor);

        combineResultsIntoFinalLists(timesPerKey, signaturesPerKey, nonRecoverableMessagesPerKey);
      } catch (Exception e) {
        e.printStackTrace();
      }
    }
  }


  /**
   * Handles the creation of signatures for a single message using a specified private key. It
   * calculates and updates the time taken to generate each signature and the non-recoverable parts
   * of messages, storing these in the provided lists. The progress of the signing process is
   * updated using the progressUpdater consumer.
   *
   * @param executor                     The ExecutorService used for concurrent processing of
   *                                     signature tasks.
   * @param messageCounter               The counter for the current message being processed.
   * @param message                      The message to be signed.
   * @param keyIndex                     The index of the private key used for signing.
   * @param privateKey                   The private key used for signing the message.
   * @param progressUpdater              A consumer to update the progress of the signing process.
   * @param timesPerKey                  A list to store the time taken for each signature
   *                                     generation.
   * @param signaturesPerKey             A list to store the generated signatures.
   * @param nonRecoverableMessagesPerKey A list to store the non-recoverable parts of the messages.
   */
  public void batchCreateSignatures(ExecutorService executor, int messageCounter, String message,
      int keyIndex,
      PrivateKey privateKey,
      DoubleConsumer progressUpdater, List<List<Long>> timesPerKey,
      List<List<byte[]>> signaturesPerKey,
      List<List<byte[]>> nonRecoverableMessagesPerKey)
      throws InvalidSignatureTypeException, NoSuchAlgorithmException, InvalidDigestException, NoSuchProviderException {

    Future<List<byte[]>> future = submitSignatureTasks(executor, message, privateKey);
    collectSignatureResults(keyIndex, future, timesPerKey, signaturesPerKey,
        nonRecoverableMessagesPerKey);
    progressUpdater.accept((double) ++messageCounter / this.numTrials);


  }


  /**
   * Submits signature tasks to an ExecutorService for concurrent processing. Each task generates a
   * digital signature for a given message using a specified private key and also retrieves the
   * non-recoverable part of the message, if applicable.
   *
   * @param executor   The ExecutorService used for concurrent processing of signature tasks.
   * @param message    The message to be signed.
   * @param privateKey The private key used for signing the message.
   * @return A Future object representing the outcome of a signature task.
   */
  private Future<List<byte[]>> submitSignatureTasks(ExecutorService executor,
      String message, PrivateKey privateKey)
      throws InvalidSignatureTypeException, NoSuchAlgorithmException, InvalidDigestException, NoSuchProviderException {

    SigScheme sigScheme = SignatureFactory.getSignatureScheme(currentType, privateKey,
        isProvablySecure);
    sigScheme.setDigest(currentHashType, hashSize);
    return executor.submit(() -> {
      byte[] signature = sigScheme.sign(message.getBytes());
      byte[] nonRecoverableM = sigScheme.getNonRecoverableM();
      return List.of(signature, nonRecoverableM);
    });


  }


  /**
   * Collects the results from a single future task for a signature generation. It records the time
   * taken for each signature creation and stores the generated signatures and non-recoverable parts
   * of the messages into the provided lists.
   *
   * @param keyIndex                     The index of the private key used for signing.
   * @param future                       A future object from which to collect results.
   * @param timesPerKey                  A list to store the time taken for each signature
   *                                     generation.
   * @param signaturesPerKey             A list to store the generated signatures.
   * @param nonRecoverableMessagesPerKey A list to store the non-recoverable parts of messages.
   */
  private void collectSignatureResults(int keyIndex, Future<List<byte[]>> future,
      List<List<Long>> timesPerKey, List<List<byte[]>> signaturesPerKey,
      List<List<byte[]>> nonRecoverableMessagesPerKey) {
    List<byte[]> result = null;
    long startTime = System.nanoTime();
    try {
      result = future.get();
    } catch (ExecutionException | InterruptedException e) {
      throw new RuntimeException(e.getCause());
    }
    long endTime = System.nanoTime() - startTime;
    timesPerKey.get(keyIndex).add(endTime);
    signaturesPerKey.get(keyIndex).add(result.get(0));
    nonRecoverableMessagesPerKey.get(keyIndex).add(result.get(1));
  }


  /**
   * Combines the results from the batch signature creation into final lists. It aggregates the
   * times, signatures, and non-recoverable message parts from all keys into single lists for easy
   * access.
   *
   * @param timesPerKey                  The list of times for each key and message.
   * @param signaturesPerKey             The list of signatures for each key and message.
   * @param nonRecoverableMessagesPerKey The list of non-recoverable message parts for each key and
   *                                     message.
   */
  private void combineResultsIntoFinalLists(List<List<Long>> timesPerKey,
      List<List<byte[]>> signaturesPerKey,
      List<List<byte[]>> nonRecoverableMessagesPerKey) {

    for (int msgIndex = 0; msgIndex < this.numTrials; msgIndex++) {
      for (int keyIndex = 0; keyIndex < privKeyBatch.size(); keyIndex++) {
        signaturesFromBenchmark.add(signaturesPerKey.get(keyIndex).get(msgIndex));
        nonRecoverableMessages.add(nonRecoverableMessagesPerKey.get(keyIndex).get(msgIndex));
        clockTimesPerTrial.add(timesPerKey.get(keyIndex).get(msgIndex));
      }
    }
  }

  /**
   * Shuts down the executor service and handles the termination process. This method ensures that
   * all tasks are completed or canceled and that the executor service is properly shut down.
   *
   * @param executor The executor service to be shut down.
   */
  private void shutdownExecutorService(ExecutorService executor) {
    executor.shutdown();
    try {
      if (!executor.awaitTermination(60, java.util.concurrent.TimeUnit.SECONDS)) {
        System.err.println("Executor did not terminate in the specified time.");
        List<Runnable> droppedTasks = executor.shutdownNow();
        System.err.println("Dropped " + droppedTasks.size() + " tasks.");
      }
    } catch (InterruptedException e) {
      System.err.println("Interrupted while waiting for executor service to terminate.");
      Thread.currentThread().interrupt();
    }
  }


  /**
   * Exports the batch of signatures generated during the benchmarking process to a file. Each
   * signature is converted to a string representation and written as a separate line in the file.
   *
   * @param signatureFileName The name of the file to which the signatures will be exported.
   * @throws IOException If there is an error in creating the file or writing to it.
   */
  public void exportSignatureBatch(String signatureFileName) throws IOException {
    File signatureFile = FileHandle.createUniqueFile(signatureFileName);
    try (BufferedWriter signatureWriter = new BufferedWriter(new FileWriter(signatureFile))) {
      for (byte[] signature : signaturesFromBenchmark) {
        signatureWriter.write(new BigInteger(1, signature).toString());
        signatureWriter.newLine();
      }
    }
  }


  /**
   * Exports the batch of non-recoverable message parts to a file. Each entry consists of a flag (1
   * or 0) indicating whether a non-recoverable message part follows, and then the message part
   * itself if present. Each entry is written on a new line.
   *
   * @param fileName The name of the file to which the non-recoverable message parts will be
   *                 exported.
   * @throws IOException If there is an error in creating the file or writing to it.
   */
  public void exportNonRecoverableBatch(String fileName) throws IOException {
    File nonRecoverableBatch = FileHandle.createUniqueFile(fileName);
    try (BufferedWriter nonRecoverableWriter = new BufferedWriter(
        new FileWriter(nonRecoverableBatch))) {
      for (byte[] nonRecoverableMessage : nonRecoverableMessages) {
        if (nonRecoverableMessage.length > 0) {
          nonRecoverableWriter.write("1 ");  // Flag indicating a non-recoverable message follows
          nonRecoverableWriter.write(new String(nonRecoverableMessage));
        } else {
          nonRecoverableWriter.write("0");  // Flag indicating no non-recoverable message
        }
        nonRecoverableWriter.newLine();
      }
    }
  }


  /**
   * Processes a batch of messages and their corresponding signatures to verify the authenticity of
   * the signatures using the public keys in the batch. This method utilizes multi-threading to
   * improve efficiency and updates the progress of the verification process using the
   * progressUpdater consumer.
   *
   * @param batchMessageFile   The file containing the messages to be verified.
   * @param batchSignatureFile The file containing the corresponding signatures to be verified.
   * @param progressUpdater    A consumer to update the progress of the batch verification process.
   * @throws Exception If any error occurs during the verification process.
   */
  public void batchVerifySignatures(File batchMessageFile, File batchSignatureFile,
      DoubleConsumer progressUpdater) throws Exception {
    try (ExecutorService executor = Executors.newFixedThreadPool(
        Runtime.getRuntime().availableProcessors())) {
      this.messageFile = batchMessageFile;

      // Initialise lists to store times, verification results, signatures, and recovered messages for each key.
      List<List<Long>> timesPerKey = new ArrayList<>();
      List<List<Boolean>> verificationResultsPerKey = new ArrayList<>();
      List<List<byte[]>> signaturesPerKey = new ArrayList<>();
      List<List<byte[]>> recoveredMessagesPerKey = new ArrayList<>();
      for (int k = 0; k < publicKeyBatch.size(); k++) {
        timesPerKey.add(new ArrayList<>());
        verificationResultsPerKey.add(new ArrayList<>());
        signaturesPerKey.add(new ArrayList<>());
        recoveredMessagesPerKey.add(new ArrayList<>());
      }

      try (BufferedReader signatureReader = new BufferedReader(new FileReader(batchSignatureFile));
          BufferedReader messageReader = new BufferedReader(new FileReader(batchMessageFile))) {

        String messageLine;
        int messageCounter = 0;
        int totalWork = numTrials * publicKeyBatch.size();
        int completedWork = 0;
        while ((messageLine = messageReader.readLine()) != null
            && messageCounter < this.numTrials) {
          int keyIndex = 0;
          for (PublicKey key : publicKeyBatch) {
            int finalCompletedWork = completedWork;
            batchVerifySignatures(executor, messageCounter, messageLine, keyIndex, key,
                signatureReader,
                trialProgress -> {
                  double currentKeyProgress = trialProgress / numTrials;
                  double overallProgress =
                      ((double) finalCompletedWork / totalWork) + (currentKeyProgress
                          / publicKeyBatch.size());
                  progressUpdater.accept(overallProgress);
                }, timesPerKey, verificationResultsPerKey,
                signaturesPerKey, recoveredMessagesPerKey);
            completedWork++;
            keyIndex++;
          }
          messageCounter++;
        }
        shutdownExecutorService(executor);
        combineVerificationResultsIntoFinalLists(timesPerKey, verificationResultsPerKey,
            signaturesPerKey, recoveredMessagesPerKey);

      }
    }
  }

  /**
   * Verifies a single message-signature pair using a specified public key. It records the time
   * taken for each verification and stores the results, including the verification status and any
   * recovered message parts, in the provided lists. This method also updates the progress of the
   * verification process using the progressUpdater consumer.
   *
   * @param executor                  The ExecutorService used for concurrent processing of
   *                                  verification tasks.
   * @param messageCounter            The counter for the current message being processed.
   * @param messageLine               The message to be verified.
   * @param keyIndex                  The index of the public key used for verification.
   * @param key                       The public key used for verification.
   * @param signatureReader           The BufferedReader to read the signature corresponding to the
   *                                  message.
   * @param progressUpdater           A consumer to update the progress of the verification
   *                                  process.
   * @param timesPerKey               A list to store the time taken for each verification.
   * @param verificationResultsPerKey A list to store the results of each verification.
   * @param signaturesPerKey          A list to store the signatures.
   * @param recoveredMessagesPerKey   A list to store any recovered message parts.
   * @throws IOException If any error occurs during the verification process.
   */
  public void batchVerifySignatures(ExecutorService executor, int messageCounter,
      String messageLine, int keyIndex,
      PublicKey key, BufferedReader signatureReader,
      DoubleConsumer progressUpdater, List<List<Long>> timesPerKey,
      List<List<Boolean>> verificationResultsPerKey,
      List<List<byte[]>> signaturesPerKey, List<List<byte[]>> recoveredMessagesPerKey)
      throws IOException {

    Future<Pair<Boolean, List<byte[]>>> future = submitVerificationTasks(executor,
        messageLine, signatureReader, key);

    collectVerificationResults(keyIndex, future, timesPerKey, verificationResultsPerKey,
        signaturesPerKey,
        recoveredMessagesPerKey);
    progressUpdater.accept((double) ++messageCounter / this.numTrials);


  }


  /**
   * Submits tasks for verifying signatures against their respective messages to an ExecutorService
   * for concurrent processing. Each task performs signature verification and retrieves any
   * recoverable parts of the message.
   *
   * @param executor        The ExecutorService used for concurrent processing of verification
   *                        tasks.
   * @param messageLine     The message to be verified.
   * @param signatureReader The BufferedReader to read the signature corresponding to the message.
   * @param publicKey       The public key used for verification.
   * @return A  Future object, representing the outcome of a verification task.
   * @throws IOException If an error occurs while reading the signature.
   */
  private Future<Pair<Boolean, List<byte[]>>> submitVerificationTasks(
      ExecutorService executor,
      String messageLine,
      BufferedReader signatureReader, PublicKey publicKey) throws IOException {
    String signatureLine = signatureReader.readLine();
    byte[] signatureBytes = new BigInteger(signatureLine).toByteArray();
    return executor.submit(() -> {
     return verifySignature(publicKey, messageLine, signatureBytes);
    });


  }

  /**
   * Verifies a signature against a message using a specified public key. This method encapsulates
   * the logic for signature verification, handling different types of signature schemes, including
   * those with message recovery.
   *
   * @param publicKey      The public key used for signature verification.
   * @param messageLine    The message to be verified against the signature.
   * @param signatureBytes The signature to be verified.
   * @return A Pair containing the result of verification and the relevant data (original message,
   * signature, and recovered message if applicable).
   * @throws InvalidSignatureTypeException If the signature type is invalid.
   * @throws DataFormatException           If the data format is incorrect.
   */
  private Pair<Boolean, List<byte[]>> verifySignature(PublicKey publicKey, String messageLine,
      byte[] signatureBytes)
      throws InvalidSignatureTypeException, DataFormatException, NoSuchAlgorithmException, InvalidDigestException, NoSuchProviderException {
    SigScheme sigScheme = SignatureFactory.getSignatureScheme(currentType, publicKey,
        isProvablySecure);
    sigScheme.setDigest(currentHashType, hashSize);
    boolean verificationResult;
    byte[] recoveredMessage = new byte[]{};

    if (currentType == SignatureType.ISO_IEC_9796_2_SCHEME_1) {
      String[] nonRecoverableParts = messageLine.split(" ", 2);
      byte[] nonRecoverableMessage =
          nonRecoverableParts[0].equals("1") ? nonRecoverableParts[1].getBytes() : null;
      verificationResult = sigScheme.verify(nonRecoverableMessage, signatureBytes);
      recoveredMessage = verificationResult ? sigScheme.getRecoverableM() : new byte[]{};
    } else {
      verificationResult = sigScheme.verify(messageLine.getBytes(), signatureBytes);
    }

    return new Pair<>(verificationResult,
        List.of(messageLine.getBytes(), signatureBytes, recoveredMessage));
  }


  /**
   * Collects the results of the signature verification tasks. It records the time taken for each
   * verification and stores the results, including the status of verification, the signature, and
   * any recovered message parts, in the provided lists.
   *
   * @param keyIndex                  The index of the public key used for verification.
   * @param future                    A future object from which to collect results.
   * @param timesPerKey               A list to store the time taken for each verification.
   * @param verificationResultsPerKey A list to store the results of each verification.
   * @param signaturesPerKey          A list to store the signatures.
   * @param recoveredMessagesPerKey   A list to store any recovered message parts.
   */

  private void collectVerificationResults(int keyIndex,
      Future<Pair<Boolean, List<byte[]>>> future,
      List<List<Long>> timesPerKey, List<List<Boolean>> verificationResultsPerKey,
      List<List<byte[]>> signaturesPerKey, List<List<byte[]>> recoveredMessagesPerKey) {

    Pair<Boolean, List<byte[]>> result = null;
    long startTime = System.nanoTime();
    try {
      result = future.get();
    } catch (ExecutionException | InterruptedException e) {
      throw new RuntimeException(e.getCause());
    }
    long endTime = System.nanoTime() - startTime;

    timesPerKey.get(keyIndex).add(endTime);
    verificationResultsPerKey.get(keyIndex).add(result.getKey());
    signaturesPerKey.get(keyIndex).add(result.getValue().get(1));
    recoveredMessagesPerKey.get(keyIndex).add(result.getValue().get(2));


  }

  /**
   * Aggregates the results from all verification trials into final lists. This method combines the
   * times, verification results, signatures, and recovered messages from each public key into
   * single lists for streamlined access and analysis.
   *
   * @param timesPerKey               The list of times for each public key and message.
   * @param verificationResultsPerKey The list of verification results for each public key and
   *                                  message.
   * @param signaturesPerKey          The list of signatures for each public key and message.
   * @param recoveredMessagesPerKey   The list of recovered message parts for each public key and
   *                                  message.
   */
  private void combineVerificationResultsIntoFinalLists(List<List<Long>> timesPerKey,
      List<List<Boolean>> verificationResultsPerKey,
      List<List<byte[]>> signaturesPerKey, List<List<byte[]>> recoveredMessagesPerKey) {
    verificationResults = verificationResultsPerKey.stream().flatMap(List::stream)
        .collect(Collectors.toList());
    signaturesFromBenchmark = signaturesPerKey.stream().flatMap(List::stream)
        .collect(Collectors.toList());
    recoverableMessages = recoveredMessagesPerKey.stream().flatMap(List::stream)
        .collect(Collectors.toList());
    clockTimesPerTrial = timesPerKey.stream().flatMap(List::stream).collect(Collectors.toList());
  }


  /**
   * Exports verification results to a CSV file. Each line in the file will contain the index of the
   * key used for verification, the signed message, the signature, and the recoverable message (if
   * any).
   *
   * @throws IOException If there is an error in writing to the file.
   */
  public void exportVerificationResultsToCSV(int keyIndex) throws IOException {
    File file = FileHandle.createUniqueFile(
        "verificationResults_" + getPublicKeyLengths().get(keyIndex) + "bits.csv");

    try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
      // Write header
      writer.write(
          "KeyIndex" + " (" + getPublicKeyLengths().get(keyIndex) + "bit)"
              + "Verification Result, Original Message, Signature, Recovered Message\n");

      int numKeys = publicKeyBatch.size();
      int numMessagesPerKey = verificationResults.size() / numKeys;

      // Read original messages for each key
      try (BufferedReader reader = new BufferedReader(new FileReader(messageFile))) {
        String originalMessage;
        int messageCounter = 0;

        while ((originalMessage = reader.readLine()) != null
            && messageCounter < numMessagesPerKey) {
          boolean verificationResult = verificationResults.get(messageCounter);

          int keySpecificMessageResults = (keyIndex * numMessagesPerKey) + messageCounter;
          String signature = new BigInteger(1,
              signaturesFromBenchmark.get(keySpecificMessageResults)).toString();
          String recoverableMessage =
              recoverableMessages.get(keySpecificMessageResults) != null
                  && recoverableMessages.get(keySpecificMessageResults).length > 0 ?
                  new String(recoverableMessages.get(keySpecificMessageResults)) : "";

          writer.write((keyIndex + 1) + ", " +
              verificationResult + ", " +
              "\"" + originalMessage + "\", " + // Enclose in quotes to handle commas
              signature + ", " + recoverableMessage + "\n");

          messageCounter++;
        }
      }

    }
  }


  /**
   * Retrieves the clock times recorded for each trial during the batch signature creation process.
   * Each entry in the list represents the total time taken for a single trial.
   *
   * @return A list of long values, each representing the duration of a trial in nanoseconds.
   */
  public List<Long> getClockTimesPerTrial() {
    return clockTimesPerTrial;
  }

  /**
   * Retrieves the list of signatures generated during the benchmarking process. Each byte array in
   * the list represents a single signature corresponding to a message.
   *
   * @return A list of byte arrays, where each array is a digital signature.
   */
  public List<byte[]> getSignaturesFromBenchmark() {
    return signaturesFromBenchmark;
  }

  /**
   * Retrieves the list of non-recoverable message parts generated during the signing process. These
   * parts are generated in signature schemes that involve message recovery.
   *
   * @return A list of byte arrays, where each array is a non-recoverable part of a message.
   */
  public List<byte[]> getNonRecoverableMessages() {
    return nonRecoverableMessages;
  }

  /**
   * Retrieves the list of recoverable message parts generated during the verification process.
   * These parts are recovered in signature schemes that support message recovery.
   *
   * @return A list of byte arrays, where each array is a recoverable part of a message.
   */
  public List<byte[]> getRecoverableMessages() {
    return recoverableMessages;
  }


  /**
   * Indicates whether the signature scheme operates in provably secure mode.
   *
   * @return {@code true} if the signature scheme is operating in provably secure mode, {@code
   * false} otherwise.
   */
  public boolean getProvablySecure() {
    return isProvablySecure;
  }

  /**
   * Sets whether the signature scheme should operate in provably secure mode.
   *
   * @param isProvablySecure A boolean flag to enable or disable provably secure mode.
   */
  public void setProvablySecure(boolean isProvablySecure) {
    this.isProvablySecure = isProvablySecure;
  }

  /**
   * Retrieves the lengths of the public keys in bits. This method is useful for identifying the
   * strength of the keys used in the signature process.
   *
   * @return A list of integer values, each representing the bit length of a public key in the
   * batch.
   */
  public List<Integer> getPublicKeyLengths() {
    List<Integer> result = new ArrayList<>();
    for (Key key : publicKeyBatch) {
      result.add(((key.getModulus().bitLength() + 7) / 8) * 8);
    }
    return result;
  }

  /**
   * Retrieves the lengths of the private keys in bits. This method provides insight into the
   * strength of the keys used in the signature process.
   *
   * @return A list of integer values, each representing the bit length of a private key in the
   * batch.
   */
  public List<Integer> getPrivKeyLengths() {
    List<Integer> result = new ArrayList<>();
    for (PrivateKey key : privKeyBatch) {
      result.add(((key.getModulus().bitLength() + 7) / 8) * 8);
    }
    return result;
  }


}
