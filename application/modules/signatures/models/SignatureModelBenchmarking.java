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
import uk.msci.project.rsa.Key;
import uk.msci.project.rsa.AbstractSignatureModelBenchmarking;
import uk.msci.project.rsa.PrivateKey;
import uk.msci.project.rsa.PublicKey;
import uk.msci.project.rsa.FileHandle;
import uk.msci.project.rsa.SignatureFactory;
import uk.msci.project.rsa.SigScheme;


/**
 * This class is part of the Model component specific to digital signature
 * operations providing
 * methods to sign batches of data and verification of batch signatures.  It
 * encapsulates the data
 * and the logic required to keep track of a user initiated digital signature
 * scheme.
 */
public class SignatureModelBenchmarking extends AbstractSignatureModelBenchmarking {


  /**
   * A list of lists containing non-recoverable message parts for each key
   * used in the batch
   * signature process. Each sublist corresponds to a key from the key batch
   * and contains
   * non-recoverable message parts generated during the signature creation.
   */
  List<List<String>> nonRecoverableMessagesPerKey = new ArrayList<>();

  /**
   * Constructs a new {@code SignatureModel} without requiring an initial key
   * representative of the
   * fact that at program launch, the model does not have any state: until it
   * is initiated by the
   * user
   */
  public SignatureModelBenchmarking() {
  }


  /**
   * Processes a batch of messages to create digital signatures using the
   * current private key batch.The method also updates the progress of the
   * batch signing process
   * using the provided
   * progressUpdater consumer.
   *
   * @param batchMessageFile The file containing the messages to be signed in
   *                         the batch process.
   * @param progressUpdater  A consumer to update the progress of the batch
   *                         signing process.
   * @throws IOException if there is an I/O error reading from the
   *                     batchMessageFile.
   */
  public void batchCreateSignatures(File batchMessageFile,
                                    DoubleConsumer progressUpdater)
    throws IOException {

    try (BufferedReader messageReader =
           new BufferedReader(new FileReader(batchMessageFile))) {
      this.messageFile = batchMessageFile;
      setKeyLengths(keyBatch);

      // Initialise lists to store times and results for each key
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
      try (ExecutorService executor =
             Executors.newFixedThreadPool(threadPoolSize)) {
        List<Future<Pair<Integer, Pair<Long, Pair<byte[], byte[]>>>>> futures = new ArrayList<>();
        // Reading each message and processing it.
        String message;
        totalWork =
          !getRecoveryStatus() ? numTrials * keyBatch.size()
            : numTrials;
        completedWork = 0;
        int messageCounter = 0;
        // Looping through all messages.
        while ((message = messageReader.readLine()) != null && messageCounter < this.numTrials) {
          final String currentMessage = message;
          for (int keyIndex = 0; keyIndex < keyBatch.size(); keyIndex++) {
            Key key = keyBatch.get(keyIndex);
            if (key instanceof PrivateKey privateKey) {
              final int finalKeyIndex = keyIndex;
              // Submitting a task for signature creation for each message
              // and key.
              Future<Pair<Integer, Pair<Long, Pair<byte[], byte[]>>>> future
                = executor.submit(
                () -> createSignature(privateKey, currentMessage,
                  finalKeyIndex));
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
      combineResultsIntoFinalLists(timesPerKey, signaturesPerKey,
        nonRecoverableMessagesPerKey);
    }
  }

  /**
   * Processes a list of futures representing the results of signature
   * creation tasks. This method
   * iterates over each future, extracts the results, and updates the
   * corresponding lists for times,
   * signatures, and non-recoverable message parts. It also updates the
   * progress of the signature
   * creation process.
   *
   * @param progressUpdater              Consumer to update the progress of
   *                                     the signature creation.
   * @param futures                      List of futures to process.
   * @param timesPerKey                  List to store the time taken for
   *                                     signature creation per
   *                                     key.
   * @param signaturesPerKey             List to store the created signatures
   *                                     per key.
   * @param nonRecoverableMessagesPerKey List to store any non-recoverable
   *                                     message parts per key.
   */
  private void processFuturesForSignatureCreation(DoubleConsumer progressUpdater,
                                                  List<Future<Pair<Integer,
                                                    Pair<Long, Pair<byte[],
                                                      byte[]>>>>> futures,
                                                  List<List<Long>> timesPerKey,
                                                  List<List<byte[]>> signaturesPerKey,
                                                  List<List<byte[]>> nonRecoverableMessagesPerKey) {
    for (Future<Pair<Integer, Pair<Long, Pair<byte[], byte[]>>>> future :
      futures) {
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
   * Creates a digital signature for a given message using a specified
   * private key. This method is
   * used as part of the batch signature creation process in the {@code
   * batchCreateSignatures}
   * method. It calculates the signature using the provided private key and
   * message, and also tracks
   * the time taken for the operation. Additionally, it returns
   * non-recoverable parts of the
   * message, if any.
   *
   * @param privateKey The private key used to create the signature.
   * @param message    The message to be signed.
   * @param keyIndex   The index of the private key in the key batch, used
   *                   for tracking purposes.
   * @return A {@code Pair} object containing the key index and a nested
   * {@code Pair}. The nested
   * {@code Pair} includes the time taken to generate the signature and
   * another nested {@code Pair}
   * containing the signature and any non-recoverable message parts.
   * @throws InvalidSignatureTypeException if the type of signature is invalid.
   * @throws NoSuchAlgorithmException      if the algorithm for signature is
   *                                       not available.
   * @throws InvalidDigestException        if there is an issue with the
   *                                       digest algorithm.
   * @throws NoSuchProviderException       if the provider for the
   *                                       cryptographic service is not
   *                                       available.
   * @throws DataFormatException           if the message data format is not
   *                                       suitable for signing.
   */
  private Pair<Integer, Pair<Long, Pair<byte[], byte[]>>> createSignature(
    PrivateKey privateKey, String message, int keyIndex)
    throws InvalidSignatureTypeException, NoSuchAlgorithmException,
    InvalidDigestException, NoSuchProviderException, DataFormatException {

    int keyLength = keyLengths.get(keyIndex);
    int digestSize = customHashSizeFraction == null ? 0
      : (int) Math.round((keyLength * customHashSizeFraction[0])
      / (double) customHashSizeFraction[1]);
    digestSize = Math.floorDiv(digestSize + 7, 8);

    // Create the signature scheme with the specified settings
    SigScheme sigScheme = SignatureFactory.getSignatureScheme(currentType,
      privateKey,
      isProvablySecure);
    sigScheme.setDigest(currentHashType, digestSize);

    long startTime = System.nanoTime();
    byte[] signature = sigScheme.sign(message.getBytes());
    long endTime = System.nanoTime() - startTime;
    byte[] nonRecoverableM = sigScheme.getNonRecoverableM();

    return new Pair<>(keyIndex, new Pair<>(endTime, new Pair<>(signature,
      nonRecoverableM)));
  }


  /**
   * Processes a batch of messages and their corresponding signatures to
   * verify the authenticity of
   * the signatures using the current public key batch. This method updates
   * the progress of the
   * verification process using the progressUpdater consumer.
   *
   * @param batchMessageFile   The file containing the messages to be verified.
   * @param batchSignatureFile The file containing the corresponding
   *                           signatures to be verified.
   * @param progressUpdater    A consumer to update the progress of the batch
   *                           verification process.
   * @throws IOException if there is an I/O error reading from the
   *                     batchMessageFile.
   */
  public void batchVerifySignatures(File batchMessageFile,
                                    File batchSignatureFile,
                                    DoubleConsumer progressUpdater)
    throws IOException {

    this.messageFile = batchMessageFile;
    setKeyLengths(keyBatch);

    // Initialise lists to store times, verification results, signatures, and
    // recovered messages
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

    try (BufferedReader signatureReader =
           new BufferedReader(new FileReader(batchSignatureFile));
         BufferedReader messageReader =
           new BufferedReader(new FileReader(batchMessageFile))) {

      int threadPoolSize = Runtime.getRuntime().availableProcessors();
      try (ExecutorService executor =
             Executors.newFixedThreadPool(threadPoolSize)) {

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
              // Calculating the digest size if custom hash size fractions
              // are specified
              int digestSize = customHashSizeFraction == null ? 0
                : (int) Math.round((keyLength * customHashSizeFraction[0])
                / (double) customHashSizeFraction[1]);
              digestSize = Math.floorDiv(digestSize + 7, 8);

              // Read the signature for the current message
              String signatureLine = signatureReader.readLine();
              byte[] signatureBytes;
              try {
                signatureBytes = new BigInteger(signatureLine).toByteArray();
                // proceed with signatureBytes
              } catch (NumberFormatException e) {
                signatureBytes = new BigInteger("0").toByteArray();
              }
              // Submitting a task for verifying each signature asynchronously

              int finalDigestSize = digestSize;
              int finalKeyIndex = keyIndex;
              String finalMessageLine = messageLine;
              byte[] finalSignatureBytes = signatureBytes;
              Future<Pair<Integer, Pair<Boolean, Pair<Long, List<byte[]>>>>> future = executor.submit(
                () -> {
                  Pair<Boolean, Pair<Long, List<byte[]>>> verificationResult
                    = verifySignature(
                    publicKey, finalMessageLine, finalSignatureBytes,
                    finalDigestSize);
                  return new Pair<>(finalKeyIndex,
                    verificationResult);
                });
              futures.add(future);
              // Process the futures once the pool is full or all messages
              // are read
              if (futures.size() >= threadPoolSize || messageCounter == this.numTrials - 1) {
                processFuturesForSignatureVerification(progressUpdater, futures,
                  timesPerKey,
                  signaturesPerKey, recoveredMessagesPerKey,
                  verificationResultsPerKey);
                futures.clear();
              }

              keyIndex++;
            }
          }

          messageCounter++;
        }
        // Process remaining futures if any
        if (futures.size() >= threadPoolSize || messageCounter < numTrials - 1) {
          processFuturesForSignatureVerification(progressUpdater, futures,
            timesPerKey,
            signaturesPerKey, recoveredMessagesPerKey,
            verificationResultsPerKey);
          futures.clear();
        }

      }

      // Combine results into final lists
      combineVerificationResultsIntoFinalLists(timesPerKey,
        verificationResultsPerKey,
        signaturesPerKey, recoveredMessagesPerKey);
    }
  }

  /**
   * Processes a batch of messages and their corresponding signatures to
   * verify the authenticity of
   * the signatures for message recovery schemes
   *
   * @param batchMessageFile   The file containing the messages to be verified.
   * @param batchSignatureFile The file containing the corresponding
   *                           signatures to be verified.
   * @param progressUpdater    A consumer to update the progress of the batch
   *                           verification process.
   * @throws IOException if there is an I/O error reading from the
   *                     batchMessageFile.
   */
  public void batchVerifySignaturesForRecovery(File batchMessageFile,
                                               File batchSignatureFile,
                                               DoubleConsumer progressUpdater)
    throws IOException {

    this.messageFile = batchMessageFile;
    setKeyLengths(keyBatch);

    // Initialise lists to store times, verification results, signatures, and
    // recovered messages
    List<List<Long>> timesPerKey = new ArrayList<>();
    List<List<Boolean>> verificationResultsPerKey = new ArrayList<>();
    List<List<byte[]>> signaturesPerKey = new ArrayList<>();
    List<List<byte[]>> recoveredMessagesPerKey = new ArrayList<>();

    for (int k = 0; k < keyBatch.size(); k++) {
      timesPerKey.add(new ArrayList<>());
      verificationResultsPerKey.add(new ArrayList<>());
      signaturesPerKey.add(new ArrayList<>());
      recoveredMessagesPerKey.add(new ArrayList<>());
      nonRecoverableMessagesPerKey.add(new ArrayList<>());
    }

    try (BufferedReader signatureReader =
           new BufferedReader(new FileReader(batchSignatureFile));
         BufferedReader messageReader =
           new BufferedReader(new FileReader(batchMessageFile))) {
      // Calculating the number of threads based on available processors
      int threadPoolSize = Runtime.getRuntime().availableProcessors();
      try (ExecutorService executor =
             Executors.newFixedThreadPool(threadPoolSize)) {

        int messageCounter = 0;
        numTrials = numTrials / keyBatch.size();

        totalWork = numTrials * keyBatch.size();

        completedWork = 0;
        List<Future<Pair<Integer, Pair<Boolean, Pair<Long, List<byte[]>>>>>> futures = new ArrayList<>();

        while (messageCounter < numTrials) {
          int keyIndex = 0;
          for (Key key : keyBatch) {
            if (key instanceof PublicKey publicKey) {
              int keyLength = keyLengths.get(keyIndex);
              // Calculating the digest size if custom hash size fractions
              // are specified

              int digestSize = customHashSizeFraction == null ? 0
                : (int) Math.round((keyLength * customHashSizeFraction[0])
                / (double) customHashSizeFraction[1]);
              digestSize = Math.floorDiv(digestSize + 7, 8);

              // Read signature for each message
              String messageLine = messageReader.readLine();
              nonRecoverableMessagesPerKey.get(keyIndex).add(messageLine);
              String signatureLine = signatureReader.readLine();
              byte[] signatureBytes;
              try {
                signatureBytes = new BigInteger(signatureLine).toByteArray();
              } catch (NumberFormatException e) {
                signatureBytes = new BigInteger("0").toByteArray();
              }
              // Submitting a task for verifying each signature asynchronously

              int finalDigestSize = digestSize;
              int finalKeyIndex = keyIndex;

              byte[] finalSignatureBytes = signatureBytes;
              Future<Pair<Integer, Pair<Boolean, Pair<Long, List<byte[]>>>>> future = executor.submit(
                () -> {
                  Pair<Boolean, Pair<Long, List<byte[]>>> verificationResult
                    = verifySignature(
                    publicKey, messageLine, finalSignatureBytes,
                    finalDigestSize);
                  return new Pair<>(finalKeyIndex, verificationResult);
                });
              futures.add(future);
              // Process the futures once the pool is full or all messages
              // are read
              if (futures.size() >= threadPoolSize || messageCounter == this.numTrials - 1) {
                processFuturesForSignatureVerification(progressUpdater, futures,
                  timesPerKey,
                  signaturesPerKey, recoveredMessagesPerKey,
                  verificationResultsPerKey);
                futures.clear();
              }


            }
            keyIndex++;
          }

          messageCounter++;
        }
        // Process remaining futures if any

        if (futures.size() >= threadPoolSize || messageCounter < numTrials - 1) {
          processFuturesForSignatureVerification(progressUpdater, futures,
            timesPerKey,
            signaturesPerKey, recoveredMessagesPerKey,
            verificationResultsPerKey);
          futures.clear();
        }

      }

      // Combine results into final lists
      combineVerificationResultsIntoFinalLists(timesPerKey,
        verificationResultsPerKey,
        signaturesPerKey, recoveredMessagesPerKey);
    }
  }

  /**
   * Processes a list of futures representing the results of signature
   * verification tasks. This
   * method iterates over each future, extracts the results, and updates the
   * corresponding lists for
   * times, verification results, signatures, and recovered messages. It also
   * updates the progress
   * of the signature verification process.
   *
   * @param progressUpdater           Consumer to update the progress of the
   *                                  signature
   *                                  verification.
   * @param futures                   List of futures to process.
   * @param timesPerKey               List to store the time taken for
   *                                  signature verification per
   *                                  key.
   * @param signaturesPerKey          List to store the verified signatures
   *                                  per key.
   * @param recoveredMessagesPerKey   List to store any recovered messages
   *                                  per key.
   * @param verificationResultsPerKey List to store the results of signature
   *                                  verification per key.
   */
  private void processFuturesForSignatureVerification(DoubleConsumer progressUpdater,
                                                      List<Future<Pair<Integer, Pair<Boolean, Pair<Long, List<byte[]>>>>>> futures,
                                                      List<List<Long>> timesPerKey,
                                                      List<List<byte[]>> signaturesPerKey,
                                                      List<List<byte[]>> recoveredMessagesPerKey, List<List<Boolean>> verificationResultsPerKey) {
    for (Future<Pair<Integer, Pair<Boolean, Pair<Long, List<byte[]>>>>> future : futures) {
      try {
        Pair<Integer, Pair<Boolean, Pair<Long, List<byte[]>>>> result =
          future.get();
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
   * Combines the results from the batch signature creation into final lists.
   * It aggregates the
   * times, signatures, and non-recoverable message parts from all keys into
   * single lists for easy
   * access.
   *
   * @param timesPerKey                  The list of times for each key and
   *                                     message.
   * @param signaturesPerKey             The list of signatures for each key
   *                                     and message.
   * @param nonRecoverableMessagesPerKey The list of non-recoverable message
   *                                     parts for each key and
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
   * Exports verification results to a CSV file for a specific key index.
   * Each line in the file will
   * contain the index of the key used for verification, the verification
   * result, the original
   * message, the signature.
   *
   * @param keyIndex        The index of the key for which verification
   *                        results are exported.
   * @param keySize         The length of the key for which verification
   *                        results are exported.
   * @param progressUpdater A consumer to update the progress of the export
   *                        process.
   * @throws IOException If there is an error writing to the file.
   */
  public void exportVerificationResultsToCSV(int keyIndex, int keySize,
                                             DoubleConsumer progressUpdater)
    throws IOException {
    // Check if the scheme involves message recovery. If so, call the
    // specialised method.
    if (getRecoveryStatus()) {
      exportVerificationResultsToCSVForRecovery(keyIndex, keySize,
        progressUpdater);
      return;
    }
    int completedWork = 0;
    File file = FileHandle.createUniqueFile(
      "verificationResults_" + keySize + "bit_"
        + String.join("_", currentType.toString().split(" ")).replace("/",
        "-") + ".csv");

    try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
      // Write the header line to the CSV file.
      writer.write(
        "KeyIndex" + keyIndex + " (" + keySize + "bit), "
          + "Verification Result, Original Message, Signature\n");
      // Calculate the number of messages per key based on the total results
      // and key batch size.
      int numKeys = keyBatch.size();
      int numMessagesPerKey = verificationResults.size() / numKeys;

      // Read original messages for each key
      try (BufferedReader reader =
             new BufferedReader(new FileReader(messageFile))) {
        String originalMessage;
        int messageCounter = 0;
        // Process each message, corresponding to the keyIndex.
        while ((originalMessage = reader.readLine()) != null
          && messageCounter < numMessagesPerKey) {
          // Calculate the index for key-specific message results.
          int keySpecificMessageResults =
            (keyIndex * numMessagesPerKey) + messageCounter;
          // Get the verification result and signature for each message.

          boolean verificationResult =
            verificationResults.get(keySpecificMessageResults);
          String signature = new BigInteger(1,
            signaturesFromBenchmark.get(keySpecificMessageResults)).toString();

          writer.write((keyIndex + 1) + ", " +
            verificationResult + ", " +
            "\"" + originalMessage + "\", " + // Enclose in quotes to handle
            // commas
            signature + "\n");

          double currentKeyProgress = (double) (++completedWork) / totalWork;
          progressUpdater.accept(currentKeyProgress);
          messageCounter++;
        }
      }

    }
  }

  /**
   * Exports message recovery verification results to a CSV file for a
   * specific key index. Each line
   * in the file will contain the index of the key used for verification, the
   * verification result,
   * the original message, the signature, and the recovered message (if any).
   *
   * @param keyIndex        The index of the key for which verification
   *                        results are exported.
   * @param keySize         The length of the key for which verification
   *                        results are exported.
   * @param progressUpdater A consumer to update the progress of the export
   *                        process.
   * @throws IOException If there is an error writing to the file.
   */
  public void exportVerificationResultsToCSVForRecovery(int keyIndex,
                                                        int keySize,
                                                        DoubleConsumer progressUpdater)
    throws IOException {
    int completedWork = 0;
    File file = FileHandle.createUniqueFile(
      "verificationResults_" + keySize + "bit_"
        + String.join("_", currentType.toString().split(" ")).replace("/",
        "-") + ".csv");

    try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
      // Write header
      writer.write(
        "KeyIndex" + keyIndex + " (" + keySize + "bit), "
          + "Verification Result, Original (Non Recoverable) Message, " +
          "Signature, Recovered Message\n");

      int numKeys = keyBatch.size();
      int numMessagesPerKey = verificationResults.size() / numKeys;

      int messageCounter = 0;
      List<String> keySpecificMessages =
        nonRecoverableMessagesPerKey.get(keyIndex);

      for (String originalMessage : keySpecificMessages) {
        int keySpecificMessageResults =
          (keyIndex * numMessagesPerKey) + messageCounter;
        boolean verificationResult =
          verificationResults.get(keySpecificMessageResults);
        String signature = new BigInteger(1,
          signaturesFromBenchmark.get(keySpecificMessageResults)).toString();
        String recoverableMessage =
          recoverableMessages.get(keySpecificMessageResults) != null
            && recoverableMessages.get(keySpecificMessageResults).length > 0 ?
            new String(recoverableMessages.get(keySpecificMessageResults)) :
            "[*NoMsg*]";

        writer.write((keyIndex + 1) + ", " +
          verificationResult + ", " +
          "\"" + originalMessage + "\", " + // Enclose in quotes to handle
          // commas
          signature + ", " + recoverableMessage + "\n");

        double currentKeyProgress = (double) (++completedWork) / totalWork;
        progressUpdater.accept(currentKeyProgress);
        messageCounter++;
      }


    }
  }


}
