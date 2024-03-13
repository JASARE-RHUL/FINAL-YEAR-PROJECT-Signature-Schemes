package uk.msci.project.rsa;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.DoubleConsumer;
import java.util.zip.DataFormatException;
import javafx.util.Pair;

/**
 * This class is part of the Model component specific to digital signature operations providing
 * methods to sign data and verify signatures.  It encapsulates the data and the logic required to
 * keep track of a user initiated digital signature scheme.
 */
public class SignatureModelComparisonBenchmarking extends AbstractSignatureModelBenchmarking {

  /**
   * list representing the hash types used under standard parameters in the cross-parameter
   * benchmarking/comparison mode.
   */
  private List<HashFunctionSelection> currentFixedHashTypeList_ComparisonMode = new ArrayList<>();

  /**
   * list representing the hash types used under provably secure parameters in the cross-parameter
   * benchmarking/comparison mode.
   */
  private List<HashFunctionSelection> currentProvableHashTypeList_ComparisonMode = new ArrayList<>();

  /**
   * The number of different key sizes that will be used for generating signatures in the comparison
   * mode. This field indicates a number of key sizes selected by the user to be tested during
   * benchmarking.
   */
  private int numKeySizesForComparisonMode;

  /**
   * The number of keys to be generated per key size in the comparison mode
   */
  private int numKeysPerKeySizeComparisonMode;

  /**
   * describes the various key parameter configurations used in the signature scheme. Each string in
   * the list represents a specific key configuration, which to be used for comparison benchmarking
   * with the other key configurations.
   */
  private List<String> keyConfigurationStrings;

  /**
   * Maps each group index to a list of pairs of {@code DigestType} and a boolean indicating if it's
   * provably secure. This map is used in comparison mode to keep track of the hash functions used
   * for each key configuration group.
   */
  private Map<Integer, List<HashFunctionSelection>> keyConfigToHashFunctionsMap = new HashMap<>();

  /**
   * The number of keys in each group for the comparison mode. This determines how many keys are
   * processed together as a group when performing signature operations in comparison mode.
   */
  private int keysPerGroup = 2;

  /**
   * An array storing the number of trials per key for each group in the comparison mode. This array
   * is used to keep track of how many trials are conducted for each key within a group,
   * facilitating accurate benchmarking and result analysis.
   */
  private int[] trialsPerKeyByGroup;

  /**
   * The total number of hash functions used across all groups in the comparison mode. This field
   * aggregates the count of all distinct hash functions applied across different key
   * configurations, providing a quantitative measure of the diversity in hash function usage.
   */
  private int totalHashFunctions;

  /**
   * The total number of groups in the comparison mode. This field reflects the number of distinct
   * groups formed based on different key configurations or hash functions, enabling structured
   * benchmarking across varying cryptographic parameters.
   */
  private int totalGroups;


  /**
   * The total number of benchmarking runs to be performed over a message set in the comparison
   * mode.
   */
  private int numBenchmarkingRuns;


  /**
   * Constructs a new {@code SignatureModel} without requiring an initial key representative of the
   * fact that at program launch, the model does not have any state: until it is initiated by the
   * user
   */
  public SignatureModelComparisonBenchmarking() {
  }


  /**
   * Processes a batch of messages to create digital signatures in the cross-parameter
   * benchmarking/comparison mode. This mode involves generating signatures using a variety of keys
   * created with different parameter settings (or key configurations chosen by the user or set by
   * default ) for each selected key size. For each key size, this method generates signatures using
   * specified number of keys  corresponding to each key configuration and hash function
   * combination. The method updates the progress of signature generation using the provided
   * progressUpdater consumer.
   *
   * @param batchMessageFile The file containing the messages to be signed in the batch process.
   * @param progressUpdater  A consumer to update the progress of the batch signing process.
   * @throws IOException if there is an I/O error reading from the batchMessageFile.
   */
  public void batchCreateSignatures(File batchMessageFile, DoubleConsumer progressUpdater)
      throws IOException, ExecutionException, InterruptedException {
    this.messageFile = batchMessageFile;
    setKeyLengths(keyBatch);

    Map<String, List<Long>> timesPerKeyHashFunction = new HashMap<>();
    Map<String, List<byte[]>> signaturesPerKeyHashFunction = new HashMap<>();
    Map<String, List<byte[]>> nonRecoverableMessagesPerKeyHashFunction = new HashMap<>();

    int threadPoolSize = Runtime.getRuntime().availableProcessors();
    try (ExecutorService executor = Executors.newFixedThreadPool(threadPoolSize)) {
      this.numKeySizesForComparisonMode = keyBatch.size() / numKeysPerKeySizeComparisonMode;

      completedWork = 0;
      numBenchmarkingRuns = calculateNumBenchmarkingRuns();
      computeTrialsPerKeyByGroup(numTrials);
      totalWork = numBenchmarkingRuns * numTrials * numKeySizesForComparisonMode;

      try (BufferedReader messageReader = new BufferedReader(new FileReader(batchMessageFile))) {
        String message;
        List<Future<Pair<String, Pair<Long, Pair<byte[], byte[]>>>>> futures = new ArrayList<>();

        while ((message = messageReader.readLine()) != null) {
          final String currentMessage = message;

          for (int keySizeIndex = 0; keySizeIndex < keyBatch.size();
              keySizeIndex += numKeysPerKeySizeComparisonMode) {
            for (int keyGroupIndex = 0; keyGroupIndex < numKeysPerKeySizeComparisonMode;
                keyGroupIndex += keysPerGroup) {
              List<HashFunctionSelection> hashFunctionTypesForGroup = keyConfigToHashFunctionsMap.get(
                  Math.floorDiv(keyGroupIndex, keysPerGroup));

              if (hashFunctionTypesForGroup != null) {
                for (HashFunctionSelection hashFunctionType : hashFunctionTypesForGroup) {
                  for (int j = keyGroupIndex;
                      j < keyGroupIndex + keysPerGroup && j < numKeysPerKeySizeComparisonMode;
                      j++) {
                    int actualKeyIndex = keySizeIndex + j;
                    PrivateKey privateKey = (PrivateKey) keyBatch.get(actualKeyIndex);
                    int keyLength = keyLengths.get(actualKeyIndex);
                    int digestSize =
                        hashFunctionType.getCustomSize() == null ? 0 : (int) Math.round(
                            (keyLength * hashFunctionType.getCustomSize()[0])
                                / (double) hashFunctionType.getCustomSize()[1]);
                    digestSize = Math.floorDiv(digestSize + 7, 8);
                    String keyHashFunctionIdentifier =
                        actualKeyIndex + "-" + hashFunctionType.getDigestType();

                    int finalDigestSize = digestSize;
                    Future<Pair<String, Pair<Long, Pair<byte[], byte[]>>>> future = executor.submit(
                        () -> {
                          try {
                            SigScheme sigScheme = SignatureFactory.getSignatureScheme(currentType,
                                privateKey, hashFunctionType.isProvablySecure());
                            sigScheme.setDigest(hashFunctionType.getDigestType(), finalDigestSize);

                            long startTime = System.nanoTime();
                            byte[] signature = sigScheme.sign(currentMessage.getBytes());
                            long endTime = System.nanoTime() - startTime;
                            byte[] nonRecoverableM = sigScheme.getNonRecoverableM();

                            return new Pair<>(keyHashFunctionIdentifier,
                                new Pair<>(endTime, new Pair<>(signature, nonRecoverableM)));
                          } catch (Exception e) {
                            e.printStackTrace();
                            return null;
                          }
                        });

                    futures.add(future);

                    if (futures.size() >= threadPoolSize) {
                      processFuturesForSignatureCreation(progressUpdater, futures,
                          timesPerKeyHashFunction,
                          signaturesPerKeyHashFunction, nonRecoverableMessagesPerKeyHashFunction);
                      futures.clear();
                    }
                  }
                }
              }
            }
          }

        }
        // Process remaining futures for the last batch
        processFuturesForSignatureCreation(progressUpdater, futures, timesPerKeyHashFunction,
            signaturesPerKeyHashFunction, nonRecoverableMessagesPerKeyHashFunction);
        futures.clear();
      } finally {
        executor.shutdown();
      }
    }

    // Combine the results stored in the maps for further processing or analysis
    combineResultsIntoFinalLists(timesPerKeyHashFunction, signaturesPerKeyHashFunction,
        nonRecoverableMessagesPerKeyHashFunction);
  }

  /**
   * Processes a list of futures obtained from submitting signature creation tasks to an
   * ExecutorService. Each future represents the result of a signature creation operation. This
   * method retrieves the result from each future, updates the relevant data structures with the
   * signature, time taken for the operation, and any non-recoverable message parts, and updates the
   * overall progress of the signature creation process.
   *
   * @param progressUpdater                          A consumer to update the progress of the batch
   *                                                 signature creation process.
   * @param futures                                  The list of futures representing pending
   *                                                 signature creation tasks.
   * @param timesPerKeyHashFunction                  Map of key-hash function identifiers to their
   *                                                 corresponding processing times.
   * @param signaturesPerKeyHashFunction             Map of key-hash function identifiers to their
   *                                                 corresponding generated signatures.
   * @param nonRecoverableMessagesPerKeyHashFunction Map of key-hash function identifiers to their
   *                                                 corresponding non-recoverable message parts.
   * @throws InterruptedException If the thread is interrupted while waiting for the future's
   *                              result.
   * @throws ExecutionException   If an exception occurs during the computation.
   */
  private void processFuturesForSignatureCreation(DoubleConsumer progressUpdater,
      List<Future<Pair<String, Pair<Long, Pair<byte[], byte[]>>>>> futures,
      Map<String, List<Long>> timesPerKeyHashFunction,
      Map<String, List<byte[]>> signaturesPerKeyHashFunction,
      Map<String, List<byte[]>> nonRecoverableMessagesPerKeyHashFunction)
      throws InterruptedException, ExecutionException {
    for (Future<Pair<String, Pair<Long, Pair<byte[], byte[]>>>> future : futures) {
      Pair<String, Pair<Long, Pair<byte[], byte[]>>> result = future.get();

      if (result != null) {
        String identifier = result.getKey();
        Long time = result.getValue().getKey();
        byte[] signature = result.getValue().getValue().getKey();
        byte[] nonRecoverableM = result.getValue().getValue().getValue();

        timesPerKeyHashFunction.computeIfAbsent(identifier, k -> new ArrayList<>()).add(time);
        signaturesPerKeyHashFunction.computeIfAbsent(identifier, k -> new ArrayList<>())
            .add(signature);
        nonRecoverableMessagesPerKeyHashFunction.computeIfAbsent(identifier, k -> new ArrayList<>())
            .add(nonRecoverableM);
      }
      completedWork++;
      double currentKeyProgress = (double) completedWork / totalWork;
      progressUpdater.accept(currentKeyProgress);
    }
  }


  /**
   * Combines the results of the batch signature creation into final lists for further processing or
   * analysis. This method aggregates the times, signatures, and non-recoverable message parts for
   * each key and hash function combination used in the batch creation process.
   *
   * @param timesPerKeyHashFunction                  Map of key-hash function identifiers to their
   *                                                 corresponding processing times.
   * @param signaturesPerKeyHashFunction             Map of key-hash function identifiers to their
   *                                                 corresponding generated signatures.
   * @param nonRecoverableMessagesPerKeyHashFunction Map of key-hash function identifiers to their
   *                                                 corresponding non-recoverable message parts.
   */
  void combineResultsIntoFinalLists(Map<String, List<Long>> timesPerKeyHashFunction,
      Map<String, List<byte[]>> signaturesPerKeyHashFunction,
      Map<String, List<byte[]>> nonRecoverableMessagesPerKeyHashFunction) {

    // Calculating the total number of keys and keys per key size for iteration
    int totalKeys = keyBatch.size();
    int keysPerKeySize = totalKeys / numKeySizesForComparisonMode;
    int totalMessages = numTrials; // Total number of messages in a trial

    // Iterate over each message
    for (int messageIndex = 0; messageIndex < totalMessages; messageIndex++) {

      // Iterate over each key size to handle different configurations
      for (int keySizeIndex = 0; keySizeIndex < numKeySizesForComparisonMode; keySizeIndex++) {
        // Offset to account for multiple key sizes in the key batch
        int keyOffset = keySizeIndex * keysPerKeySize;

        // Iterate through each group of keys
        for (int groupIndex = 0; groupIndex < keyConfigToHashFunctionsMap.size(); groupIndex++) {
          List<HashFunctionSelection> hashFunctions = keyConfigToHashFunctionsMap.get(groupIndex);
          int numHashFunctions = hashFunctions.size(); // Number of hash functions in the current group

          // Iterate through each key within the group
          for (int keyIndex = 0; keyIndex < keysPerGroup; keyIndex++) {
            // Calculate the actual index of the key in the batch
            int actualKeyIndex = keyOffset + groupIndex * keysPerGroup + keyIndex;

            // Ensure the key index is within the total number of keys
            if (actualKeyIndex >= totalKeys) {
              break;
            }

            // Iterate for each hash function
            for (int hashIndex = 0; hashIndex < numHashFunctions; hashIndex++) {
              String keyHashFunctionIdentifier =
                  actualKeyIndex + "-" + hashFunctions.get(hashIndex).getDigestType().toString();

              // Add signature and non-recoverable message for the current message and key-hash-function pair
              byte[] signature = signaturesPerKeyHashFunction.get(keyHashFunctionIdentifier)
                  .get(messageIndex);
              byte[] nonRecoverableMessage = nonRecoverableMessagesPerKeyHashFunction.get(
                  keyHashFunctionIdentifier).get(messageIndex);
              signaturesFromBenchmark.add(signature);
              nonRecoverableMessages.add(nonRecoverableMessage);

              // Aggregate clock times for all messages in this key-hash-function pair
              clockTimesPerTrial.add(
                  timesPerKeyHashFunction.get(keyHashFunctionIdentifier).get(messageIndex));
            }
          }
        }
      }
    }
  }


  /**
   * Processes a batch of messages and their corresponding signatures for verification in the
   * cross-parameter benchmarking/comparison mode. This mode involves verifying signatures using a
   * variety of public keys created with different parameter settings for each selected key size.
   * For each key size, this method verifies signatures using a specified number of keys with
   * corresponding to each key configuration and hash function combination. The method updates the
   * progress of signature verification using the provided progressUpdater consumer.
   *
   * @param batchMessageFile   The file containing the messages to be verified.
   * @param batchSignatureFile The file containing the corresponding signatures to be verified.
   * @param progressUpdater    A consumer to update the progress of the batch verification process.
   * @throws IOException If there is an I/O error reading from the files.
   */
  public void batchVerifySignatures(File batchMessageFile, File batchSignatureFile,
      DoubleConsumer progressUpdater)
      throws IOException {

    this.messageFile = batchMessageFile;
    this.numKeySizesForComparisonMode = keyBatch.size() / numKeysPerKeySizeComparisonMode;
    setKeyLengths(keyBatch);
    int totalKeys = keyBatch.size();
    int keysPerKeySize = totalKeys / numKeySizesForComparisonMode;
    completedWork = 0;
    numBenchmarkingRuns = calculateNumBenchmarkingRuns();
    computeTrialsPerKeyByGroup(numTrials);
    totalWork = numBenchmarkingRuns * numTrials * numKeySizesForComparisonMode;
    Map<String, List<Long>> timesPerKeyHashFunction;
    Map<String, List<Boolean>> verificationResultsPerKeyHashFunction;
    Map<String, List<byte[]>> recoveredMessagesPerKeyHashFunction;
    Map<String, List<byte[]>> signaturesPerKeyHashFunction;

    int threadPoolSize = Runtime.getRuntime().availableProcessors();

    try (ExecutorService executor = Executors.newFixedThreadPool(threadPoolSize)) {
      timesPerKeyHashFunction = new HashMap<>();
      verificationResultsPerKeyHashFunction = new HashMap<>();
      recoveredMessagesPerKeyHashFunction = new HashMap<>();
      signaturesPerKeyHashFunction = new HashMap<>();

      try (BufferedReader messageReader = new BufferedReader(
          new FileReader(batchMessageFile));
          BufferedReader signatureReader = new BufferedReader(
              new FileReader(batchSignatureFile))) {

        String messageLine;
        List<Future<Pair<Boolean, Pair<Long, List<byte[]>>>>> futures = new ArrayList<>();
        while ((messageLine = messageReader.readLine()) != null) {

          for (int keySizeIndex = 0; keySizeIndex < numKeySizesForComparisonMode; keySizeIndex++) {
            int keyOffset = keySizeIndex * keysPerKeySize;

            for (int groupIndex = 0; groupIndex < keyConfigToHashFunctionsMap.size();
                groupIndex++) {
              List<HashFunctionSelection> hashFunctions = keyConfigToHashFunctionsMap.get(
                  groupIndex);

              for (int keyIndex = 0; keyIndex < keysPerGroup; keyIndex++) {
                int actualKeyIndex = keyOffset + groupIndex * keysPerGroup + keyIndex;

                if (actualKeyIndex >= totalKeys) {
                  break; // Skip if key index exceeds the total number of keys
                }

                PublicKey publicKey = (PublicKey) keyBatch.get(actualKeyIndex);
                int keyLength = keyLengths.get(actualKeyIndex);

                for (HashFunctionSelection hashFunction : hashFunctions) {
                  String keyHashFunctionIdentifier =
                      actualKeyIndex + "-" + hashFunction.getDigestType().toString();
                  int digestSize = hashFunction.getCustomSize() == null ? 0 : (int) Math.round(
                      (keyLength * hashFunction.getCustomSize()[0])
                          / (double) hashFunction.getCustomSize()[1]);
                  digestSize = Math.floorDiv(digestSize + 7, 8);

                  String signatureLine = signatureReader.readLine();
                  byte[] signatureBytes = new BigInteger(signatureLine).toByteArray();

                  String finalMessageLine = messageLine;
                  int finalDigestSize = digestSize;
                  Future<Pair<Boolean, Pair<Long, List<byte[]>>>> future = executor.submit(() -> {
                    try {
                      SigScheme sigScheme = SignatureFactory.getSignatureScheme(currentType,
                          publicKey, hashFunction.isProvablySecure());
                      sigScheme.setDigest(hashFunction.getDigestType(), finalDigestSize);
                      return getBatchVerificationResult(sigScheme, finalMessageLine,
                          signatureBytes, keyHashFunctionIdentifier);
                    } catch (Exception e) {
                      e.printStackTrace();
                      return null;
                    }
                  });
                  futures.add(future);

                  if (futures.size() >= threadPoolSize) {
                    processFuturesForSignatureVerification(progressUpdater, futures,
                        timesPerKeyHashFunction,
                        signaturesPerKeyHashFunction, recoveredMessagesPerKeyHashFunction,
                        verificationResultsPerKeyHashFunction);
                    futures.clear();
                  }

                }
              }
            }
          }

        }
        // Process remaining futures for the last batch
        processFuturesForSignatureVerification(progressUpdater, futures,
            timesPerKeyHashFunction,
            signaturesPerKeyHashFunction, recoveredMessagesPerKeyHashFunction,
            verificationResultsPerKeyHashFunction);
        futures.clear();
      } catch (ExecutionException | InterruptedException e) {
        e.printStackTrace();
      } finally {
        executor.shutdown();
      }
    }

    combineVerificationResultsIntoFinalLists(timesPerKeyHashFunction, signaturesPerKeyHashFunction,
        recoveredMessagesPerKeyHashFunction, verificationResultsPerKeyHashFunction);
  }

  /**
   * Processes a list of futures obtained from submitting signature verification tasks to an
   * ExecutorService. Each future represents the result of a signature verification operation. This
   * method retrieves the result from each future, updates the relevant data structures with the
   * verification result, time taken for the operation, and any recovered message parts, and updates
   * the overall progress of the signature verification process.
   *
   * @param progressUpdater                       A consumer to update the progress of the batch
   *                                              signature verification process.
   * @param futures                               The list of futures representing pending signature
   *                                              verification tasks.
   * @param timesPerKeyHashFunction               Map of key-hash function identifiers to their
   *                                              corresponding verification times.
   * @param signaturesPerKeyHashFunction          Map of key-hash function identifiers to their
   *                                              corresponding verified signatures.
   * @param recoveredMessagesPerKeyHashFunction   Map of key-hash function identifiers to their
   *                                              corresponding recovered messages.
   * @param verificationResultsPerKeyHashFunction Map of key-hash function identifiers to their
   *                                              corresponding verification results.
   * @throws InterruptedException If the thread is interrupted while waiting for the future's
   *                              result.
   * @throws ExecutionException   If an exception occurs during the computation.
   */
  private void processFuturesForSignatureVerification(DoubleConsumer progressUpdater,
      List<Future<Pair<Boolean, Pair<Long, List<byte[]>>>>> futures,
      Map<String, List<Long>> timesPerKeyHashFunction,
      Map<String, List<byte[]>> signaturesPerKeyHashFunction,
      Map<String, List<byte[]>> recoveredMessagesPerKeyHashFunction,
      Map<String, List<Boolean>> verificationResultsPerKeyHashFunction)
      throws InterruptedException, ExecutionException {
    for (Future<Pair<Boolean, Pair<Long, List<byte[]>>>> future : futures) {
      Pair<Boolean, Pair<Long, List<byte[]>>> result = future.get();
      Long time = result.getValue().getKey();

      byte[] recoveredMessage = result.getValue().getValue().get(2);
      byte[] signature = result.getValue().getValue().get(1);
      String keyHashFunctionID = new String(result.getValue().getValue().get(3));
      Boolean verificationResult = result.getKey();

      timesPerKeyHashFunction.computeIfAbsent(keyHashFunctionID,
          k -> new ArrayList<>()).add(time);
      verificationResultsPerKeyHashFunction.computeIfAbsent(keyHashFunctionID,
          k -> new ArrayList<>()).add(verificationResult);
      recoveredMessagesPerKeyHashFunction.computeIfAbsent(keyHashFunctionID,
          k -> new ArrayList<>()).add(recoveredMessage);
      signaturesPerKeyHashFunction.computeIfAbsent(keyHashFunctionID,
          k -> new ArrayList<>()).add(signature);

      double currentKeyProgress = (double) (++completedWork) / totalWork;
      progressUpdater.accept(currentKeyProgress);
    }
  }


  /**
   * Combines the results of the batch signature verification into final lists for further
   * processing or analysis. This method aggregates the verification times, results, signatures, and
   * recovered messages for each key and hash function combination used in the batch verification
   * process.
   *
   * @param timesPerKeyHashFunction               Map of key-hash function identifiers to their
   *                                              corresponding verification times.
   * @param signaturesPerKeyHashFunction          Map of key-hash function identifiers to their
   *                                              corresponding verified signatures.
   * @param recoveredMessagesPerKeyHashFunction   Map of key-hash function identifiers to their
   *                                              corresponding recovered messages.
   * @param verificationResultsPerKeyHashFunction Map of key-hash function identifiers to their
   *                                              corresponding verification results.
   */
  void combineVerificationResultsIntoFinalLists(Map<String, List<Long>> timesPerKeyHashFunction,
      Map<String, List<byte[]>> signaturesPerKeyHashFunction,
      Map<String, List<byte[]>> recoveredMessagesPerKeyHashFunction,
      Map<String, List<Boolean>> verificationResultsPerKeyHashFunction) {

    int totalKeys = keyBatch.size();
    int keysPerKeySize = totalKeys / numKeySizesForComparisonMode;

    // Iterate over each key size to handle different configurations
    for (int keySizeIndex = 0; keySizeIndex < numKeySizesForComparisonMode; keySizeIndex++) {
      // Offset to account for multiple key sizes in the key batch
      int keyOffset = keySizeIndex * keysPerKeySize;

      // Iterate through each group of keys
      for (int groupIndex = 0; groupIndex < keyConfigToHashFunctionsMap.size(); groupIndex++) {
        List<HashFunctionSelection> hashFunctions = keyConfigToHashFunctionsMap.get(groupIndex);

        // Iterate through each key within the group
        for (int keyIndex = 0; keyIndex < keysPerGroup; keyIndex++) {
          // Calculate the actual index of the key in the batch
          int actualKeyIndex = keyOffset + groupIndex * keysPerGroup + keyIndex;

          // Ensure the key index is within the total number of keys
          if (actualKeyIndex >= totalKeys) {
            break;
          }

          // Iterate for each hash function for the current key
          for (HashFunctionSelection hashFunction : hashFunctions) {
            String keyHashFunctionIdentifier =
                actualKeyIndex + "-" + hashFunction.getDigestType().toString();

            List<byte[]> signaturesForKey = signaturesPerKeyHashFunction.get(
                keyHashFunctionIdentifier);
            List<byte[]> recoveredMessagesPerKey = recoveredMessagesPerKeyHashFunction.get(
                keyHashFunctionIdentifier);
            List<Long> timesForKey = timesPerKeyHashFunction.get(keyHashFunctionIdentifier);
            List<Boolean> verificationResultsPerKey = verificationResultsPerKeyHashFunction.get(
                keyHashFunctionIdentifier);

            signaturesFromBenchmark.addAll(signaturesForKey);
            verificationResults.addAll(verificationResultsPerKey);
            recoverableMessages.addAll(recoveredMessagesPerKey);
            clockTimesPerTrial.addAll(timesForKey);
          }
        }
      }
    }
  }


  /**
   * Performs the verification of a single message-signature pair using the specified signature
   * scheme and hash function identifier. It returns the verification result, the time taken for
   * verification, the original message, signature bytes, and recovered message if any.
   *
   * @param sigScheme              The signature scheme to be used for verification.
   * @param messageLine            The original message to be verified.
   * @param signatureBytes         The signature bytes to be verified against the message.
   * @param hashFunctionIdentifier The identifier of the hash function used.
   * @return Pair<Boolean, Pair < Long, List < byte [ ]>>> Returns a pair containing the
   * verification result and a pair of the time taken for verification and a list of bytes arrays
   * including the original message, signature, and recovered message if applicable.
   * @throws DataFormatException if there is an error corresponding verification results.
   */
  Pair<Boolean, Pair<Long, List<byte[]>>> getBatchVerificationResult(SigScheme sigScheme,
      String messageLine, byte[] signatureBytes, String hashFunctionIdentifier)
      throws DataFormatException {
    boolean verificationResult;
    byte[] recoveredMessage = new byte[]{};
    long endTime = 0;
    long startTime = 0;
    if (currentType == SignatureType.ISO_IEC_9796_2_SCHEME_1) {
      String[] nonRecoverableParts = messageLine.split(" ", 2);
      byte[] nonRecoverableMessage =
          nonRecoverableParts[0].equals("1") ? nonRecoverableParts[1].getBytes() : null;
      startTime = System.nanoTime();
      verificationResult = sigScheme.verify(nonRecoverableMessage, signatureBytes);
      endTime = System.nanoTime() - startTime;
      recoveredMessage = verificationResult ? sigScheme.getRecoverableM() : new byte[]{};
    } else {
      startTime = System.nanoTime();
      verificationResult = sigScheme.verify(messageLine.getBytes(), signatureBytes);
      endTime = System.nanoTime() - startTime;
    }

    return new Pair<>(verificationResult,
        new Pair<>(endTime, List.of(messageLine.getBytes(), signatureBytes, recoveredMessage,
            hashFunctionIdentifier.getBytes())));
  }


  /**
   * Exports verification results to a CSV file in the cross-parameter benchmarking mode. This
   * method generates a CSV file with results from signature verification processes conducted under
   * different parameter settings for a specific key size. The CSV file includes details such as the
   * parameter type, verification result, original message, signature, and any recovered message.
   * This functionality facilitates detailed analysis and comparison of signature verification
   * performance across different parameter configurations.
   *
   * @param keySizeIndex The index of the key size for which results are to be exported. This index
   *                     corresponds to the position of the key size in the list of all key sizes
   *                     used during the benchmarking process.
   * @throws IOException If there is an error in writing to the file.
   */
  void exportVerificationResultsToCSV(int keySizeIndex) throws IOException {
    File file = FileHandle.createUniqueFile(
        "verificationResults_ComparisonMode_" + getKeyLengths().get(keySizeIndex)
            + "bits.csv");

    int currentIndex = 0;
    int headerStartIndex = 0; // Starting index for the row headers for each group
    int resultsPerKeySize = totalWork / numKeySizesForComparisonMode;
    try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
      // Write header
      writer.write(
          "Parameter Type" + " (" + getKeyLengths().get(keySizeIndex)
              + "bit key), Hash Function, "
              + "Verification Result, Original Message, Signature, Recovered Message\n");
      while (currentIndex < clockTimesPerTrial.size()) {
        for (int groupIndex = 0; groupIndex < keyConfigToHashFunctionsMap.size(); groupIndex++) {
          List<HashFunctionSelection> hashFunctions = keyConfigToHashFunctionsMap.get(
              groupIndex);

          for (int hashFunctionIndex = 0; hashFunctionIndex < hashFunctions.size();
              hashFunctionIndex++) {
            for (int k = 0; k < keysPerGroup; k++) {
              int keyIndex =
                  groupIndex * keysPerGroup + k
                      + (totalGroups * keysPerGroup) * (Math.floorDiv(currentIndex,
                      resultsPerKeySize));
              if (keyIndex >= keyBatch.size()) {
                break; // Prevent accessing keys beyond the total number of keys
              }
              int trialsPerHashFunction = trialsPerKeyByGroup[groupIndex] / hashFunctions.size();
              String keyConfigString = keyConfigurationStrings.get(
                  (headerStartIndex + k) % keyConfigurationStrings.size());
              String hashFunctionName = hashFunctions.get(hashFunctionIndex).getDigestType()
                  .toString();
              // Read original messages for each key
              try (BufferedReader reader = new BufferedReader(new FileReader(messageFile))) {
                String originalMessage;
                int messageCounter = 0;
                //numtrials = nummessages
                while ((originalMessage = reader.readLine()) != null
                    && messageCounter < numTrials) {
                  int keySpecificMessageResults = currentIndex + messageCounter;
                  boolean verificationResult = verificationResults.get(keySpecificMessageResults);
                  String signature = new BigInteger(1,
                      signaturesFromBenchmark.get(keySpecificMessageResults)).toString();
                  String recoverableMessage =
                      recoverableMessages.get(keySpecificMessageResults) != null
                          && recoverableMessages.get(keySpecificMessageResults).length > 0 ?
                          new String(recoverableMessages.get(keySpecificMessageResults)) : "";

                  writer.write(keyConfigString + ", "
                      + hashFunctionName + ", " +
                      verificationResult + ", " +
                      "\"" + originalMessage + "\", " +
                      signature + ", " + recoverableMessage + "\n");

                  messageCounter++;
                }
              }

              currentIndex += trialsPerHashFunction;
            }
          }
          headerStartIndex += keysPerGroup; // Move to the next set of headers for the next group
        }
      }
    }
  }


  /**
   * Retrieves the current list of fixed hash types set for the comparison mode, representing hash
   * types under standard parameters.
   *
   * @return List of pairs of DigestType and Boolean indicating provable security.
   */
  public List<HashFunctionSelection> getCurrentFixedHashTypeList_ComparisonMode() {
    return currentFixedHashTypeList_ComparisonMode;
  }

  /**
   * Retrieves the current list of provable hash types set for the comparison mode, representing
   * hash types under provably secure parameters.
   *
   * @return List of pairs of DigestType and Boolean indicating provable security.
   */
  public List<HashFunctionSelection> getCurrentProvableHashTypeList_ComparisonMode() {
    return currentProvableHashTypeList_ComparisonMode;
  }

  /**
   * Initialises the keyConfigToHashFunctionsMap with values based on the number of key sizes and
   * groups for default comparison mode (provaly secure vs standard). This map determines the hash
   * functions used for each group of keys.
   */
  public void createDefaultKeyConfigToHashFunctionsMap() {
    keyConfigToHashFunctionsMap = new HashMap<>();

    // Calculate the total number of groups
    totalGroups = numKeysPerKeySizeComparisonMode / keysPerGroup;
    this.numKeySizesForComparisonMode = keyBatch.size() / numKeysPerKeySizeComparisonMode;

    for (int groupIndex = 0; groupIndex < totalGroups; groupIndex++) {
      // Determine the hash function list for the current group
      List<HashFunctionSelection> hashFunctionsForGroup;
      if (groupIndex % 2 == 0) {
        hashFunctionsForGroup = getCurrentFixedHashTypeList_ComparisonMode();
      } else {
        hashFunctionsForGroup = getCurrentProvableHashTypeList_ComparisonMode();
      }

      // Assign the hash function list to the group
      keyConfigToHashFunctionsMap.put(groupIndex, new ArrayList<>(hashFunctionsForGroup));
    }
    calculateTotalHashFunctions();
  }

  /**
   * Retrieves the number of different key sizes selected for generating/verifying signatures in the
   * cross-parameter comparison mode of benchmarking. This method is relevant in scenarios where the
   * signature creation/verification process is tested across various key sizes, each potentially
   * having different parameter settings (standard vs. provably secure). It provides the count of
   * distinct key sizes that have been chosen for benchmarking, facilitating the process of
   * comparing performance across these varied configurations.
   *
   * @return The number of different key sizes selected for generating signatures in the comparison
   * mode.
   */
  public int getNumKeySizesForComparisonMode() {
    return numKeySizesForComparisonMode;
  }

  /**
   * Sets the number of keys to be generated per key size in the comparison mode. Each key size will
   * have this specified number of keys generated.
   *
   * @param numKeysPerKeySizeComparisonMode The number of keys to be generated for each key size.
   */
  public void setNumKeysPerKeySizeComparisonMode(int numKeysPerKeySizeComparisonMode) {
    this.numKeysPerKeySizeComparisonMode = numKeysPerKeySizeComparisonMode;
  }

  /**
   * Sets the key configuration strings that describe various key parameter configurations used in
   * the signature scheme. Each string in the list represents a specific key configuration, which to
   * be used for benchmarking different key configurations in the signature process.
   *
   * @param keyConfigurationStrings A list of strings representing different key configurations.
   */
  public void setKeyConfigurationStrings(List<String> keyConfigurationStrings) {
    this.keyConfigurationStrings = keyConfigurationStrings;

  }

  /**
   * Sets the number of keys to be considered as a group for the purpose of applying different hash
   * functions in the cross-parameter benchmarking/comparison mode.
   *
   * @param keysPerGroup The number of keys per group.
   */
  public void setKeysPerGroup(int keysPerGroup) {
    this.keysPerGroup = keysPerGroup;
  }

  /**
   * Retrieves the number of keys that are considered as a group in the cross-parameter
   * benchmarking/comparison mode.
   *
   * @return The number of keys per group.
   */
  public int getKeysPerGroup() {
    return keysPerGroup;
  }

  /**
   * Sets the mapping of key configurations to corresponding hash functions for use in the
   * cross-parameter benchmarking/comparison mode.
   *
   * @param keyConfigToHashFunctionsMap The map linking key configurations to hash functions.
   */
  public void setKeyConfigToHashFunctionsMap(
      Map<Integer, List<HashFunctionSelection>> keyConfigToHashFunctionsMap) {
    this.keyConfigToHashFunctionsMap = keyConfigToHashFunctionsMap;
    this.totalGroups = this.keyConfigToHashFunctionsMap.size();
    calculateTotalHashFunctions();
  }

  /**
   * Retrieves the mapping of key configurations to corresponding hash functions used in the
   * cross-parameter benchmarking/comparison mode.
   *
   * @return The map linking key configurations to hash functions.
   */
  public Map<Integer, List<HashFunctionSelection>> getKeyConfigToHashFunctionsMap() {
    return keyConfigToHashFunctionsMap;
  }

  /**
   * Retrieves the number of trials assigned to each key by group in the comparison mode. This
   * method is essential for accessing the specific number of trials conducted for each key, which
   * is crucial for accurate performance analysis and benchmarking in comparison mode.
   *
   * @return An array of integers, each representing the number of trials for a key in each group.
   */
  public int[] getTrialsPerKeyByGroup() {
    return trialsPerKeyByGroup;
  }

  /**
   * Calculates the total number of hash functions used across all groups in the comparison mode.
   * This method iterates through the hash functions mapped to each group and aggregates their
   * count, providing a comprehensive view of the hash function diversity in the benchmarking
   * process.
   */
  public void calculateTotalHashFunctions() {
    totalHashFunctions = 0;
    for (List<HashFunctionSelection> hashFunctionsForGroup : keyConfigToHashFunctionsMap.values()) {
      totalHashFunctions += hashFunctionsForGroup.size();
    }
  }

  /**
   * Retrieves the total number of hash functions used across all groups in the comparison mode
   * benchmarking.
   *
   * @return The total number of hash functions used in the benchmarking process.
   */
  public int getTotalHashFunctions() {
    return totalHashFunctions;
  }

  /**
   * Retrieves the total number of groups formed in the comparison mode. Each group represents a
   * unique combination of key configurations or hash * functions.
   *
   * @return The total number of groups.
   */
  public int getTotalGroups() {
    return totalGroups;
  }

  /**
   * Computes and sets the number of trials to be conducted per key for each group in the comparison
   * mode. This method takes the total number of trials and distributes them across groups based on
   * the number of hash functions in each group.
   *
   * @param numTrials The total number of trials to be conducted.
   */
  public void computeTrialsPerKeyByGroup(int numTrials) {
    trialsPerKeyByGroup = new int[totalGroups];
    for (int groupIndex = 0; groupIndex < totalGroups; groupIndex++) {
      List<HashFunctionSelection> hashFunctions = keyConfigToHashFunctionsMap.get(groupIndex);
      int numHashFunctionsInGroup = hashFunctions != null ? hashFunctions.size() : 0;
      trialsPerKeyByGroup[groupIndex] = numTrials * numHashFunctionsInGroup;
    }
  }

  /**
   * Calculates the total number of benchmarking runs needed for the comparison mode. This method
   * considers the number of groups, keys per group, and the number of hash functions within each
   * group to determine the total number of benchmarking runs required.
   *
   * @return The total number of benchmarking runs.
   */
  public int calculateNumBenchmarkingRuns() {
    int totalWork = 0;
    for (int groupIndex = 0; groupIndex < totalGroups; groupIndex++) {
      List<HashFunctionSelection> hashFunctions = keyConfigToHashFunctionsMap.get(groupIndex);
      int numHashFunctionsInGroup = hashFunctions != null ? hashFunctions.size() : 0;
      totalWork += keysPerGroup * numHashFunctionsInGroup;
    }
    return totalWork;
  }


  /**
   * Retrieves the  total number of benchmarking runs to be performed over a message set
   *
   * @return The total number of benchmarking runs.
   */
  public int getNumBenchmarkingRuns() {
    return numBenchmarkingRuns;
  }


  /**
   * Retrieves the total amount of work to be done for the comparison mode benchmarking. This value
   * represents the total number of signature operations (signing and verification) across all keys,
   * hash functions, and trials in the comparison mode.
   *
   * @return The total work for the comparison mode benchmarking.
   */
  public int getTotalWork() {
    return totalWork;
  }

}
