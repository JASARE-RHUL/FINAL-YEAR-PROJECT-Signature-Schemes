package uk.msci.project.rsa;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.Consumer;
import java.util.function.DoubleConsumer;
import java.util.zip.DataFormatException;
import javafx.util.Pair;
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
   * Stores the original messages that were signed during the verification process. Each entry in
   * this list corresponds to a signed message from a verification trial.
   */
  private List<byte[]> signedMessages = new ArrayList<>();

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
   * The number of trials to run in the batchCreateSignatures method. This determines how many
   * messages from the batch file are processed.
   */
  private int numTrials = 0;

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
  public void instantiateSignatureScheme() throws InvalidSignatureTypeException {
    if (key != null && currentType != null) {
      currentSignatureScheme = SignatureFactory.getSignatureScheme(currentType, key,
          isProvablySecure);
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
   * Creates digital signatures in a batch process using multiple threads. The method reads messages
   * from a file and signs each message using a batch of private keys. It records the time taken for
   * each trial and stores generated signatures and non-recoverable message parts.
   *
   * @param batchMessageFile The file containing messages to be signed.
   * @param progressUpdater  A consumer to update progress during the batch process.
   * @throws Exception If an error occurs during the signing process or file reading.
   */
  public void batchCreateSignatures(File batchMessageFile, DoubleConsumer progressUpdater)
      throws Exception {
    try (ExecutorService executor = Executors.newFixedThreadPool(
        Runtime.getRuntime().availableProcessors())) {

      try (BufferedReader messageReader = new BufferedReader(new FileReader(batchMessageFile))) {
        int i = 0;
        String message;
        while ((message = messageReader.readLine()) != null && i < this.numTrials) {
          CountDownLatch latch = new CountDownLatch(privKeyBatch.size());
          ConcurrentHashMap<PrivateKey, List<byte[]>> resultsMap = new ConcurrentHashMap<>();
          long startTrialTime = System.nanoTime();
          for (PrivateKey privateKey : privKeyBatch) {
            String finalMessage = message;
            executor.execute(() -> {
              try {
                SigScheme sigScheme = SignatureFactory.getSignatureScheme(currentType, privateKey,
                    isProvablySecure);
                byte[] signature = sigScheme.sign(finalMessage.getBytes());
                byte[] nonRecoverableM = sigScheme.getNonRecoverableM();
                resultsMap.put(privateKey, List.of(signature, nonRecoverableM));
              } catch (DataFormatException | InvalidSignatureTypeException e) {
                throw new RuntimeException(e);
              } finally {
                latch.countDown();
              }
            });
          }

          latch.await(); // Wait for all tasks of this trial to complete
          clockTimesPerTrial.add(System.nanoTime() - startTrialTime); // Total trial time

          // Add results in the order of privKeyBatch
          for (PrivateKey key : privKeyBatch) {
            List<byte[]> results = resultsMap.get(key);
            if (results != null) {
              signaturesFromBenchmark.add(results.get(0));
              nonRecoverableMessages.add(results.get(1));
            }
          }
          progressUpdater.accept((double) ++i / numTrials);
        }
      } finally {
        executor.shutdown();
        if (!executor.awaitTermination(60, java.util.concurrent.TimeUnit.SECONDS)) {
          System.err.println("Executor did not terminate in the specified time.");
          List<Runnable> droppedTasks = executor.shutdownNow();
          System.err.println("Dropped " + droppedTasks.size() + " tasks.");
        }
      }
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
   * Performs batch verification of signatures using multiple public keys. This method reads
   * messages and their corresponding signatures from files, and verifies each signature against the
   * message using the public keys in the batch. It updates the progress of verification and stores
   * the results, including any recoverable message parts.
   *
   * @param batchMessageFile   The file containing messages to be verified.
   * @param batchSignatureFile The file containing signatures corresponding to the messages.
   * @param progressUpdater    A consumer to update progress during the batch process.
   * @throws Exception If an error occurs during the verification process or file reading.
   */
  public void batchVerifySignatures(File batchMessageFile, File batchSignatureFile,
      DoubleConsumer progressUpdater) throws Exception {
    // Create an executor service with a fixed thread pool size based on available processors
    try (ExecutorService executor = Executors.newFixedThreadPool(
        Runtime.getRuntime().availableProcessors())) {

      // Open readers for both message and signature files
      try (BufferedReader signatureReader = new BufferedReader(new FileReader(batchSignatureFile));
          BufferedReader messageReader = new BufferedReader(new FileReader(batchMessageFile))) {

        String messageLine;
        int i = 0;
        // Read each line from the message file and ensure we don't exceed the set number of trials
        while ((messageLine = messageReader.readLine()) != null && i < this.numTrials) {
          // CountDownLatch to wait for all threads in a single trial
          CountDownLatch latch = new CountDownLatch(publicKeyBatch.size());
          // ConcurrentHashMap to store results from different threads
          ConcurrentHashMap<PublicKey, Pair<Boolean, List<byte[]>>> resultsMap = new ConcurrentHashMap<>();
          // Record the start time of the trial
          long startTrialTime = System.nanoTime();

          // Iterate through each public key in the batch
          for (PublicKey publicKey : publicKeyBatch) {
            // Read a new signature line for each public key
            String signatureLine = signatureReader.readLine();
            if (signatureLine == null) {
              break; // Break if there are no more signatures
            }
            String finalSignatureLine = signatureLine;
            final String[] finalMessageLine = {messageLine};

            // Execute signature verification in a separate thread
            executor.execute(() -> {
              try {
                // Convert the signature line to a byte array
                byte[] signatureBytes = new BigInteger(finalSignatureLine).toByteArray();
                // Create a signature scheme instance
                SigScheme sigScheme = SignatureFactory.getSignatureScheme(currentType, publicKey,
                    isProvablySecure);

                // Handle message recovery for ISO_IEC_9796_2_SCHEME_1
                if (currentType == SignatureType.ISO_IEC_9796_2_SCHEME_1) {
                  String[] nonRecoverableParts = finalMessageLine[0].split(" ", 2);
                  byte[] nonRecoverableMessage = null;
                  boolean verificationResult;

                  // Verify signature and recover message if applicable
                  if (nonRecoverableParts[0].equals("1")) {
                    nonRecoverableMessage = nonRecoverableParts[1].getBytes();
                    verificationResult = sigScheme.verify(nonRecoverableMessage, signatureBytes);
                  } else {
                    verificationResult = sigScheme.verify(null, signatureBytes);
                  }
                  byte[] recoveredM =
                      verificationResult ? sigScheme.getRecoverableM() : new byte[]{};
                  resultsMap.put(publicKey, new Pair<>(verificationResult,
                      List.of(nonRecoverableParts[1].getBytes(), signatureBytes, recoveredM)));
                } else {
                  // Verify signature for schemes without message recovery
                  boolean verificationResult = sigScheme.verify(finalMessageLine[0].getBytes(),
                      signatureBytes);
                  resultsMap.put(publicKey, new Pair<>(verificationResult,
                      List.of(finalMessageLine[0].getBytes(), signatureBytes)));
                }
              } catch (DataFormatException | InvalidSignatureTypeException e) {
                throw new RuntimeException(e);
              } finally {
                // Count down the latch after each task completion
                latch.countDown();
              }
            });
          }

          latch.await(); // Wait for all tasks of this trial to complete
          clockTimesPerTrial.add(System.nanoTime() - startTrialTime); // Calculate total trial time

          // Process and store results for each key
          for (PublicKey key : publicKeyBatch) {
            Pair<Boolean, List<byte[]>> results = resultsMap.get(key);
            if (results != null) {
              verificationResults.add(results.getKey());
              signedMessages.add(results.getValue().get(0)); // Store original message
              signaturesFromBenchmark.add(results.getValue().get(1)); // Store signature
              recoverableMessages.add(results.getValue().size() > 2 ? results.getValue().get(2)
                  : null); // Store recovered message if any
            }
          }
          progressUpdater.accept((double) ++i / numTrials); // Update progress after each trial
        }
      } catch (Exception e) {
        e.printStackTrace();
      } finally {
        // Shutdown executor and handle termination
        executor.shutdown();
        if (!executor.awaitTermination(60, java.util.concurrent.TimeUnit.SECONDS)) {
          System.err.println("Executor did not terminate in the specified time.");
          List<Runnable> droppedTasks = executor.shutdownNow();
          System.err.println("Dropped " + droppedTasks.size() + " tasks.");
        }
      }
    }
  }


  /**
   * Exports verification results to a CSV file. Each line in the file will contain the index of the
   * key used for verification, the signed message, the signature, and the recoverable message (if
   * any).
   *
   * @throws IOException If there is an error in writing to the file.
   */
  public void exportVerificationResultsToCSV() throws IOException {

    File file = FileHandle.createUniqueFile("verif.csv");

    try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
      // Write header
      writer.write("KeyIndex, Verification Result, Signed Message, Signature, Recovered Message\n");

      // Write each line of data
      for (int i = 0; i < verificationResults.size(); i++) {
        int keyIndex = (i % publicKeyBatch.size()) + 1; // Cycle through key indexes
        boolean verificationResult = verificationResults.get(i);
        String signedMessage = new String(signedMessages.get(i)); // Assuming UTF-8 encoding
        String signature = new BigInteger(1, signaturesFromBenchmark.get(i)).toString();
        String recoverableMessage =
            recoverableMessages.get(i) != null && recoverableMessages.get(i).length > 0 ?
                new String(recoverableMessages.get(i)) : "";

        writer.write(keyIndex + ", " +
            verificationResult + ", " +
            signedMessage + ", " +
            signature + ", " +
            recoverableMessage + "\n");
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

}
