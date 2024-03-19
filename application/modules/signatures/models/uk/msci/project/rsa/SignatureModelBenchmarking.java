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
import java.util.zip.DataFormatException;
import javafx.util.Pair;
import uk.msci.project.rsa.exceptions.InvalidDigestException;
import uk.msci.project.rsa.exceptions.InvalidSignatureTypeException;

/**
 * This class is part of the Model component specific to digital signature operations providing
 * methods to sign data and verify signatures.  It encapsulates the data and the logic required to
 * keep track of a user initiated digital signature scheme.
 */
public class SignatureModelBenchmarking extends AbstractSignatureModelBenchmarking {

  /**
   * Constructs a new {@code SignatureModel} without requiring an initial key representative of the
   * fact that at program launch, the model does not have any state: until it is initiated by the
   * user
   */
  public SignatureModelBenchmarking() {
  }


  /**
   * Processes a batch of messages to create digital signatures using the private keys in the
   * batch.The method also updates the progress of the batch signing process using the provided
   * progressUpdater consumer.
   *
   * @param batchMessageFile The file containing the messages to be signed in the batch process.
   * @param progressUpdater  A consumer to update the progress of the batch signing process.
   * @throws IOException if there is an I/O error reading from the batchMessageFile.
   */
  public void batchCreateSignatures(File batchMessageFile, DoubleConsumer progressUpdater)
      throws IOException {

    try (BufferedReader messageReader = new BufferedReader(new FileReader(batchMessageFile))) {
      this.messageFile = batchMessageFile;
      setKeyLengths(keyBatch);

      // Initialize lists to store times and results for each key
      List<List<Long>> timesPerKey = new ArrayList<>();
      List<List<byte[]>> signaturesPerKey = new ArrayList<>();
      List<List<byte[]>> nonRecoverableMessagesPerKey = new ArrayList<>();

      for (int k = 0; k < keyBatch.size(); k++) {
        timesPerKey.add(new ArrayList<>());
        signaturesPerKey.add(new ArrayList<>());
        nonRecoverableMessagesPerKey.add(new ArrayList<>());
      }
      int threadPoolSize = Runtime.getRuntime().availableProcessors();

      // Initialise ExecutorService for parallel execution
      try (ExecutorService executor = Executors.newFixedThreadPool(threadPoolSize)) {
        List<Future<Pair<Integer, Pair<Long, Pair<byte[], byte[]>>>>> futures = new ArrayList<>();

        String message;
        totalWork = numTrials * keyBatch.size();
        completedWork = 0;
        int messageCounter = 0;
        while ((message = messageReader.readLine()) != null && messageCounter < this.numTrials) {
          final String currentMessage = message;
          for (int keyIndex = 0; keyIndex < keyBatch.size(); keyIndex++) {
            Key key = keyBatch.get(keyIndex);
            if (key instanceof PrivateKey privateKey) {
              final int finalKeyIndex = keyIndex;
              Future<Pair<Integer, Pair<Long, Pair<byte[], byte[]>>>> future = executor.submit(
                  () -> createSignature(privateKey, currentMessage, finalKeyIndex));
              futures.add(future);
              if (futures.size() >= threadPoolSize || messageCounter == this.numTrials - 1) {
                processFuturesForSignatureCreation(progressUpdater, futures,
                    timesPerKey,
                    signaturesPerKey, nonRecoverableMessagesPerKey);
                futures.clear();
              }
            }
          }

          messageCounter++;
        }
        // Process remaining futures for the last batch
        processFuturesForSignatureCreation(progressUpdater, futures,
            timesPerKey,
            signaturesPerKey, nonRecoverableMessagesPerKey);
        futures.clear();

      }

      // Combine results into final lists
      combineResultsIntoFinalLists(timesPerKey, signaturesPerKey, nonRecoverableMessagesPerKey);
    }
  }

  /**
   * Processes a list of futures representing the results of signature creation tasks. This method
   * iterates over each future, extracts the results, and updates the corresponding lists for times,
   * signatures, and non-recoverable message parts. It also updates the progress of the signature
   * creation process.
   *
   * @param progressUpdater              Consumer to update the progress of the signature creation.
   * @param futures                      List of futures to process.
   * @param timesPerKey                  List to store the time taken for signature creation per
   *                                     key.
   * @param signaturesPerKey             List to store the created signatures per key.
   * @param nonRecoverableMessagesPerKey List to store any non-recoverable message parts per key.
   */
  private void processFuturesForSignatureCreation(DoubleConsumer progressUpdater,
      List<Future<Pair<Integer, Pair<Long, Pair<byte[], byte[]>>>>> futures,
      List<List<Long>> timesPerKey,
      List<List<byte[]>> signaturesPerKey,
      List<List<byte[]>> nonRecoverableMessagesPerKey) {
    for (Future<Pair<Integer, Pair<Long, Pair<byte[], byte[]>>>> future : futures) {
      try {
        Pair<Integer, Pair<Long, Pair<byte[], byte[]>>> result = future.get();
        if (result != null) {
          int keyIndex = result.getKey();
          Long time = result.getValue().getKey();
          byte[] signature = result.getValue().getValue().getKey();
          byte[] nonRecoverableM = result.getValue().getValue().getValue();

          timesPerKey.get(keyIndex).add(time);
          signaturesPerKey.get(keyIndex).add(signature);
          nonRecoverableMessagesPerKey.get(keyIndex).add(nonRecoverableM);

          double currentKeyProgress = (double) (++completedWork) / totalWork;
          progressUpdater.accept(currentKeyProgress);
        }
      } catch (InterruptedException | ExecutionException e) {
        e.printStackTrace();
      }
    }
  }

  /**
   * Creates a digital signature for a given message using a specified private key. This method is
   * used as part of the batch signature creation process in the {@code batchCreateSignatures}
   * method. It calculates the signature using the provided private key and message, and also tracks
   * the time taken for the operation. Additionally, it returns non-recoverable parts of the
   * message, if any.
   *
   * @param privateKey The private key used to create the signature.
   * @param message    The message to be signed.
   * @param keyIndex   The index of the private key in the key batch, used for tracking purposes.
   * @return A {@code Pair} object containing the key index and a nested {@code Pair}. The nested
   * {@code Pair} includes the time taken to generate the signature and another nested {@code Pair}
   * containing the signature and any non-recoverable message parts.
   * @throws InvalidSignatureTypeException if the type of signature is invalid.
   * @throws NoSuchAlgorithmException      if the algorithm for signature is not available.
   * @throws InvalidDigestException        if there is an issue with the digest algorithm.
   * @throws NoSuchProviderException       if the provider for the cryptographic service is not
   *                                       available.
   * @throws DataFormatException           if the message data format is not suitable for signing.
   */
  private Pair<Integer, Pair<Long, Pair<byte[], byte[]>>> createSignature(
      PrivateKey privateKey, String message, int keyIndex)
      throws InvalidSignatureTypeException, NoSuchAlgorithmException, InvalidDigestException, NoSuchProviderException, DataFormatException {

    int keyLength = keyLengths.get(keyIndex);
    int digestSize = customHashSizeFraction == null ? 0
        : (int) Math.round((keyLength * customHashSizeFraction[0])
            / (double) customHashSizeFraction[1]);
    digestSize = Math.floorDiv(digestSize + 7, 8);

    // Create the signature scheme with the specified settings
    SigScheme sigScheme = SignatureFactory.getSignatureScheme(currentType, privateKey,
        isProvablySecure);
    sigScheme.setDigest(currentHashType, digestSize);

    long startTime = System.nanoTime();
    byte[] signature = sigScheme.sign(message.getBytes());
    long endTime = System.nanoTime() - startTime;
    byte[] nonRecoverableM = sigScheme.getNonRecoverableM();

    return new Pair<>(keyIndex, new Pair<>(endTime, new Pair<>(signature, nonRecoverableM)));
  }


  /**
   * Processes a batch of messages and their corresponding signatures to verify the authenticity of
   * the signatures using the public keys in the batch. This method updates the progress of the
   * verification process using the progressUpdater consumer.
   *
   * @param batchMessageFile   The file containing the messages to be verified.
   * @param batchSignatureFile The file containing the corresponding signatures to be verified.
   * @param progressUpdater    A consumer to update the progress of the batch verification process.
   * @throws IOException if there is an I/O error reading from the batchMessageFile.
   */
  public void batchVerifySignatures(File batchMessageFile, File batchSignatureFile,
      DoubleConsumer progressUpdater)
      throws IOException {

    this.messageFile = batchMessageFile;
    setKeyLengths(keyBatch);

    // Initialise lists to store times, verification results, signatures, and recovered messages
    List<List<Long>> timesPerKey = new ArrayList<>();
    List<List<Boolean>> verificationResultsPerKey = new ArrayList<>();
    List<List<byte[]>> signaturesPerKey = new ArrayList<>();
    List<List<byte[]>> recoveredMessagesPerKey = new ArrayList<>();

    for (int k = 0; k < keyBatch.size(); k++) {
      timesPerKey.add(new ArrayList<>());
      verificationResultsPerKey.add(new ArrayList<>());
      signaturesPerKey.add(new ArrayList<>());
      recoveredMessagesPerKey.add(new ArrayList<>());
    }

    try (BufferedReader signatureReader = new BufferedReader(new FileReader(batchSignatureFile));
        BufferedReader messageReader = new BufferedReader(new FileReader(batchMessageFile))) {

      int threadPoolSize = Runtime.getRuntime().availableProcessors();
      try (ExecutorService executor = Executors.newFixedThreadPool(threadPoolSize)) {

        String messageLine;
        int messageCounter = 0;
        totalWork = numTrials * keyBatch.size();
        completedWork = 0;
        List<Future<Pair<Integer, Pair<Boolean, Pair<Long, List<byte[]>>>>>> futures = new ArrayList<>();

        while ((messageLine = messageReader.readLine()) != null
            && messageCounter < this.numTrials) {
          int keyIndex = 0;
          for (Key key : keyBatch) {
            if (key instanceof PublicKey publicKey) {
              int keyLength = keyLengths.get(keyIndex);
              int digestSize = customHashSizeFraction == null ? 0
                  : (int) Math.round((keyLength * customHashSizeFraction[0])
                      / (double) customHashSizeFraction[1]);
              digestSize = Math.floorDiv(digestSize + 7, 8);

              // Read signature for each message
              String signatureLine = signatureReader.readLine();
              byte[] signatureBytes = new BigInteger(signatureLine).toByteArray();
              int finalDigestSize = digestSize;
              int finalKeyIndex = keyIndex;
              String finalMessageLine = messageLine;
              Future<Pair<Integer, Pair<Boolean, Pair<Long, List<byte[]>>>>> future = executor.submit(
                  () -> {
                    Pair<Boolean, Pair<Long, List<byte[]>>> verificationResult = verifySignature(
                        publicKey, finalMessageLine, signatureBytes, finalDigestSize);
                    return new Pair<>(finalKeyIndex, verificationResult);
                  });
              futures.add(future);
              if (futures.size() >= threadPoolSize || messageCounter == this.numTrials - 1) {
                processFuturesForSignatureVerification(progressUpdater, futures,
                    timesPerKey,
                    signaturesPerKey, recoveredMessagesPerKey, verificationResultsPerKey);
                futures.clear();
              }

              keyIndex++;
            }
          }

          messageCounter++;
        }
        if (futures.size() >= threadPoolSize) {
          processFuturesForSignatureVerification(progressUpdater, futures,
              timesPerKey,
              signaturesPerKey, recoveredMessagesPerKey, verificationResultsPerKey);
          futures.clear();
        }

      }

      // Combine results into final lists
      combineVerificationResultsIntoFinalLists(timesPerKey, verificationResultsPerKey,
          signaturesPerKey, recoveredMessagesPerKey);
    }
  }

  /**
   * Processes a list of futures representing the results of signature verification tasks. This
   * method iterates over each future, extracts the results, and updates the corresponding lists for
   * times, verification results, signatures, and recovered messages. It also updates the progress
   * of the signature verification process.
   *
   * @param progressUpdater           Consumer to update the progress of the signature
   *                                  verification.
   * @param futures                   List of futures to process.
   * @param timesPerKey               List to store the time taken for signature verification per
   *                                  key.
   * @param signaturesPerKey          List to store the verified signatures per key.
   * @param recoveredMessagesPerKey   List to store any recovered messages per key.
   * @param verificationResultsPerKey List to store the results of signature verification per key.
   */
  private void processFuturesForSignatureVerification(DoubleConsumer progressUpdater,
      List<Future<Pair<Integer, Pair<Boolean, Pair<Long, List<byte[]>>>>>> futures,
      List<List<Long>> timesPerKey,
      List<List<byte[]>> signaturesPerKey,
      List<List<byte[]>> recoveredMessagesPerKey, List<List<Boolean>> verificationResultsPerKey) {
    for (Future<Pair<Integer, Pair<Boolean, Pair<Long, List<byte[]>>>>> future : futures) {
      try {
        Pair<Integer, Pair<Boolean, Pair<Long, List<byte[]>>>> result = future.get();
        if (result != null) {
          int i = result.getKey();
          Long time = result.getValue().getValue().getKey();

          // Store results
          timesPerKey.get(i).add(time);
          verificationResultsPerKey.get(i).add(result.getValue().getKey());
          signaturesPerKey.get(i).add(result.getValue().getValue().getValue().get(1));
          recoveredMessagesPerKey.get(i)
              .add(result.getValue().getValue().getValue().get(2));

          double currentKeyProgress = (double) (++completedWork) / totalWork;
          progressUpdater.accept(currentKeyProgress);
        }
      } catch (InterruptedException | ExecutionException e) {
        e.printStackTrace();
      }
    }
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
  void combineResultsIntoFinalLists(List<List<Long>> timesPerKey,
      List<List<byte[]>> signaturesPerKey,
      List<List<byte[]>> nonRecoverableMessagesPerKey) {

    for (int msgIndex = 0; msgIndex < this.numTrials; msgIndex++) {
      for (int keyIndex = 0; keyIndex < keyBatch.size(); keyIndex++) {
        signaturesFromBenchmark.add(signaturesPerKey.get(keyIndex).get(msgIndex));
        nonRecoverableMessages.add(nonRecoverableMessagesPerKey.get(keyIndex).get(msgIndex));
        clockTimesPerTrial.add(timesPerKey.get(keyIndex).get(msgIndex));
      }
    }
  }


  /**
   * Exports verification results to a CSV file for a specific key index. Each line in the file will
   * contain the index of the key used for verification, the verification result, the original
   * message, the signature, and the recovered message (if any).
   *
   * @param keyIndex        The index of the key for which verification results are
   *                        exported.
   * @param keySize         The length of the key for which verification results are
   *                        exported.
   * @param progressUpdater A consumer to update the progress of the export process.
   * @throws IOException If there is an error writing to the file.
   */
  public void exportVerificationResultsToCSV(int keyIndex, int keySize, DoubleConsumer progressUpdater)
      throws IOException {
    int completedWork = 0;
    File file = FileHandle.createUniqueFile(
        "verificationResults_" + keySize + "bit_"
            + String.join("_", currentType.toString().split(" ")) + ".csv");

    try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
      // Write header
      writer.write(
          "KeyIndex" + keyIndex  + " (" + keySize + "bit), "
              + "Verification Result, Original Message, Signature, Recovered Message\n");

      int numKeys = keyBatch.size();
      int numMessagesPerKey = verificationResults.size() / numKeys;

      // Read original messages for each key
      try (BufferedReader reader = new BufferedReader(new FileReader(messageFile))) {
        String originalMessage;
        int messageCounter = 0;

        while ((originalMessage = reader.readLine()) != null
            && messageCounter < numMessagesPerKey) {
          int keySpecificMessageResults = (keyIndex * numMessagesPerKey) + messageCounter;
          boolean verificationResult = verificationResults.get(keySpecificMessageResults);
          String signature = new BigInteger(1,
              signaturesFromBenchmark.get(keySpecificMessageResults)).toString();
          String recoverableMessage =
              recoverableMessages.get(keySpecificMessageResults) != null
                  && recoverableMessages.get(keySpecificMessageResults).length > 0 ?
                  new String(recoverableMessages.get(keySpecificMessageResults)) : "[*NoMsg*]";

          writer.write((keyIndex + 1) + ", " +
              verificationResult + ", " +
              "\"" + originalMessage + "\", " + // Enclose in quotes to handle commas
              signature + ", " + recoverableMessage + "\n");

          double currentKeyProgress = (double) (++completedWork) / totalWork;
          progressUpdater.accept(currentKeyProgress);
          messageCounter++;
        }
      }

    }
  }


}
