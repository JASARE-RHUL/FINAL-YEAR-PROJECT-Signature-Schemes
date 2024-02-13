package uk.msci.project.rsa;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
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
   * Creates digital signatures in batch mode for a set of messages using multiple private keys.
   * This method is designed to benchmark the performance of signature creation for a set messages
   * per each user specified key.
   *
   * @param batchMessageFile The file containing the messages to be signed.
   * @param progressUpdater  A consumer to update the progress of the signature generation process.
   * @throws Exception If an error occurs during the signing process or file reading.
   */
  public void batchCreateSignatures(File batchMessageFile, DoubleConsumer progressUpdater)
      throws Exception {
    // Set up an executor service for parallel processing, using available processors.
    try (ExecutorService executor = Executors.newFixedThreadPool(
        Runtime.getRuntime().availableProcessors())) {

      // Initialize lists to store times and results (signatures and non-recoverable parts) for each key.
      List<List<Long>> timesPerKey = new ArrayList<>();
      List<List<byte[]>> signaturesPerKey = new ArrayList<>();
      List<List<byte[]>> nonRecoverableMessagesPerKey = new ArrayList<>();
      for (int k = 0; k < privKeyBatch.size(); k++) {
        timesPerKey.add(new ArrayList<>());
        signaturesPerKey.add(new ArrayList<>());
        nonRecoverableMessagesPerKey.add(new ArrayList<>());
      }

      // Read messages from the file and process each message for all keys in the batch.
      try (BufferedReader messageReader = new BufferedReader(new FileReader(batchMessageFile))) {
        int messageCounter = 0;
        String message;
        while ((message = messageReader.readLine()) != null && messageCounter < this.numTrials) {
          // List to hold future results of asynchronous tasks.
          List<Future<List<byte[]>>> futures = new ArrayList<>();
          for (int keyIndex = 0; keyIndex < privKeyBatch.size(); keyIndex++) {
            PrivateKey privateKey = privKeyBatch.get(keyIndex);
            String finalMessage = message;

            // Submit a task for each key to sign the message asynchronously.
            Future<List<byte[]>> future = executor.submit(() -> {
              SigScheme sigScheme = SignatureFactory.getSignatureScheme(currentType, privateKey,
                  isProvablySecure);
              byte[] signature = sigScheme.sign(finalMessage.getBytes());
              byte[] nonRecoverableM = sigScheme.getNonRecoverableM();
              return List.of(signature, nonRecoverableM);
            });
            futures.add(future);
          }

          // Collect results after all tasks are submitted.
          for (int keyIndex = 0; keyIndex < futures.size(); keyIndex++) {
            long startTime = System.nanoTime();
            try {
              List<byte[]> result = futures.get(keyIndex).get();
              long endTime = System.nanoTime() - startTime;
              synchronized (timesPerKey.get(keyIndex)) {
                timesPerKey.get(keyIndex).add(endTime);
                signaturesPerKey.get(keyIndex).add(result.get(0));
                nonRecoverableMessagesPerKey.get(keyIndex).add(result.get(1));
              }
            } catch (ExecutionException | InterruptedException e) {
              throw new RuntimeException(e.getCause());
            }
          }

          // Update progress after each message is processed.
          progressUpdater.accept((double) ++messageCounter / this.numTrials);
        }
      }

      // Combine results from all keys into final lists for signatures and non-recoverable messages.
      for (int msgIndex = 0; msgIndex < this.numTrials; msgIndex++) {
        for (int keyIndex = 0; keyIndex < privKeyBatch.size(); keyIndex++) {
          signaturesFromBenchmark.add(signaturesPerKey.get(keyIndex).get(msgIndex));
          nonRecoverableMessages.add(nonRecoverableMessagesPerKey.get(keyIndex).get(msgIndex));
        }
      }
      clockTimesPerTrial = timesPerKey.stream().flatMap(List::stream).collect(Collectors.toList());

      // Shut down the executor service and handle termination.
      executor.shutdown();
      if (!executor.awaitTermination(60, java.util.concurrent.TimeUnit.SECONDS)) {
        System.err.println("Executor did not terminate in the specified time.");
        List<Runnable> droppedTasks = executor.shutdownNow();
        System.err.println("Dropped " + droppedTasks.size() + " tasks.");
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
  /**
   * Verifies digital signatures in batch mode for a set of messages using multiple public keys.
   * This method is designed to benchmark the performance of signature verification across different
   * keys.
   *
   * @param batchMessageFile   The file containing messages to be verified.
   * @param batchSignatureFile The file containing signatures corresponding to the messages.
   * @param progressUpdater    A consumer to update the progress of the verification process.
   * @throws Exception If an error occurs during the verification process or file reading.
   */
  public void batchVerifySignatures(File batchMessageFile, File batchSignatureFile,
      DoubleConsumer progressUpdater)
      throws Exception {
    // Set up an executor service for parallel processing, using available processors.
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

      // Read messages and their corresponding signatures from files.
      try (BufferedReader signatureReader = new BufferedReader(new FileReader(batchSignatureFile));
          BufferedReader messageReader = new BufferedReader(new FileReader(batchMessageFile))) {

        String messageLine;
        int messageCounter = 0;
        while ((messageLine = messageReader.readLine()) != null
            && messageCounter < this.numTrials) {
          // List to hold future results of asynchronous verification tasks.
          List<Future<Pair<Boolean, List<byte[]>>>> futures = new ArrayList<>();

          for (int keyIndex = 0; keyIndex < publicKeyBatch.size(); keyIndex++) {
            PublicKey publicKey = publicKeyBatch.get(keyIndex);
            String signatureLine = signatureReader.readLine();
            if (signatureLine == null) {
              break; // Break if there are no more signatures.
            }
            String finalSignatureLine = signatureLine;
            String[] finalMessageLine = {messageLine};

            // Submit a verification task for each public key.
            Future<Pair<Boolean, List<byte[]>>> future = executor.submit(() -> {
              byte[] signatureBytes = new BigInteger(finalSignatureLine).toByteArray();
              SigScheme sigScheme = SignatureFactory.getSignatureScheme(currentType, publicKey,
                  isProvablySecure);

              boolean verificationResult;
              byte[] recoveredMessage = new byte[]{};

              // Special handling for signature schemes with message recovery.
              if (currentType == SignatureType.ISO_IEC_9796_2_SCHEME_1) {
                String[] nonRecoverableParts = finalMessageLine[0].split(" ", 2);
                byte[] nonRecoverableMessage =
                    nonRecoverableParts[0].equals("1") ? nonRecoverableParts[1].getBytes() : null;
                verificationResult = sigScheme.verify(nonRecoverableMessage, signatureBytes);
                recoveredMessage = verificationResult ? sigScheme.getRecoverableM() : new byte[]{};
              } else {
                verificationResult = sigScheme.verify(finalMessageLine[0].getBytes(),
                    signatureBytes);
              }
              return new Pair<>(verificationResult,
                  List.of(finalMessageLine[0].getBytes(), signatureBytes, recoveredMessage));
            });

            futures.add(future);
          }

          // Collect results after all tasks are submitted.
          for (int keyIndex = 0; keyIndex < futures.size(); keyIndex++) {
            long startTime = System.nanoTime();
            try {
              Pair<Boolean, List<byte[]>> result = futures.get(keyIndex).get();
              long endTime = System.nanoTime() - startTime;
              synchronized (timesPerKey.get(keyIndex)) {
                timesPerKey.get(keyIndex).add(endTime);
                verificationResultsPerKey.get(keyIndex).add(result.getKey());
                signaturesPerKey.get(keyIndex).add(result.getValue().get(1));
                recoveredMessagesPerKey.get(keyIndex).add(result.getValue().get(2));
              }
            } catch (ExecutionException | InterruptedException e) {
              throw new RuntimeException(e.getCause());
            }
          }

          // Update progress after each message is processed.
          progressUpdater.accept((double) ++messageCounter / this.numTrials);
        }
      }

      // Combine results from all keys into final lists for verification results, signatures, and recovered messages.
      verificationResults = verificationResultsPerKey.stream().flatMap(List::stream)
          .collect(Collectors.toList());

      signaturesFromBenchmark = signaturesPerKey.stream().flatMap(List::stream)
          .collect(Collectors.toList());
      recoverableMessages = recoveredMessagesPerKey.stream().flatMap(List::stream)
          .collect(Collectors.toList());
      clockTimesPerTrial = timesPerKey.stream().flatMap(List::stream).collect(Collectors.toList());

      executor.shutdown();
      if (!executor.awaitTermination(60, java.util.concurrent.TimeUnit.SECONDS)) {
        System.err.println("Executor did not terminate in the specified time.");
        List<Runnable> droppedTasks = executor.shutdownNow();
        System.err.println("Dropped " + droppedTasks.size() + " tasks.");
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
    File file = FileHandle.createUniqueFile("verificationResults.csv");

    try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
      // Write header
      writer.write(
          "KeyIndex, Verification Result, Original Message, Signature, Recovered Message\n");

      int numKeys = publicKeyBatch.size();
      int numMessagesPerKey = verificationResults.size() / numKeys;

      for (int keyIndex = 0; keyIndex < numKeys; keyIndex++) {
        // Read original messages for each key
        try (BufferedReader reader = new BufferedReader(new FileReader(messageFile))) {
          String originalMessage;
          int messageCounter = 0;

          while ((originalMessage = reader.readLine()) != null
              && messageCounter < numMessagesPerKey) {
            boolean verificationResult = verificationResults.get(messageCounter);

            String signature = new BigInteger(1,
                signaturesFromBenchmark.get(messageCounter)).toString();
            String recoverableMessage =
                recoverableMessages.get(messageCounter) != null
                    && recoverableMessages.get(messageCounter).length > 0 ?
                    new String(recoverableMessages.get(messageCounter)) : "";

            writer.write((keyIndex + 1) + ", " +
                verificationResult + ", " +
                "\"" + originalMessage + "\", " + // Enclose in quotes to handle commas
                signature + ", " + recoverableMessage + "\n");

            messageCounter++;
          }
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

}
