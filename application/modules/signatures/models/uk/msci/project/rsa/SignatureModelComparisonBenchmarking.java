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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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


  private int totalWork;


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
   * specified number of keys with * corresponding to each key configuration. The method updates the
   * progress of signature generation using the provided progressUpdater consumer.
   *
   * @param batchMessageFile The file containing the messages to be signed in the batch process.
   * @param progressUpdater  A consumer to update the progress of the batch signing process.
   * @throws InvalidSignatureTypeException if the signature type is not supported.
   * @throws NoSuchAlgorithmException      if the specified algorithm does not exist.
   * @throws InvalidDigestException        if the specified digest algorithm is invalid.
   * @throws NoSuchProviderException       if the specified provider is not available.
   * @throws IOException                   if there is an I/O error reading from the
   *                                       batchMessageFile.
   * @throws DataFormatException           if the data format is incorrect for signing.
   */
  public void batchCreateSignatures(File batchMessageFile,
      DoubleConsumer progressUpdater)
      throws InvalidSignatureTypeException, NoSuchAlgorithmException, InvalidDigestException, NoSuchProviderException, IOException, DataFormatException {

    this.messageFile = batchMessageFile;
    this.numKeySizesForComparisonMode = keyBatch.size() / numKeysPerKeySizeComparisonMode;
    setKeyLengths(keyBatch);

    try (BufferedReader messageReader = new BufferedReader(new FileReader(batchMessageFile))) {
      // Initialize lists to store times and results for each key
      List<List<Long>> timesPerKey = new ArrayList<>();
      List<List<byte[]>> signaturesPerKey = new ArrayList<>();
      List<List<byte[]>> nonRecoverableMessagesPerKey = new ArrayList<>();

      for (int k = 0; k < keyBatch.size(); k++) {
        timesPerKey.add(new ArrayList<>());
        signaturesPerKey.add(new ArrayList<>());
        nonRecoverableMessagesPerKey.add(new ArrayList<>());
      }

      String message;

      int completedWork = 0;

      calculateTotalWork();

      int messageCounter = 0;

      while ((message = messageReader.readLine()) != null && messageCounter < this.numTrials) {
        for (int i = 0; i < keyBatch.size(); i += numKeysPerKeySizeComparisonMode) {
          for (int keyGroupIndex = 0; keyGroupIndex < numKeysPerKeySizeComparisonMode;
              keyGroupIndex += keysPerGroup) {
            List<HashFunctionSelection> hashFunctionTypesForGroup = keyConfigToHashFunctionsMap.get(
                Math.floorDiv(keyGroupIndex, keysPerGroup));

            if (hashFunctionTypesForGroup != null) {
              for (HashFunctionSelection hashFunctionType : hashFunctionTypesForGroup) {
                for (int j = keyGroupIndex;
                    j < keyGroupIndex + keysPerGroup && j < numKeysPerKeySizeComparisonMode; j++) {
                  int actualKeyIndex = i + j;

                  PrivateKey privateKey = (PrivateKey) keyBatch.get(actualKeyIndex);
                  int keyLength = keyLengths.get(actualKeyIndex);
                  SigScheme sigScheme = SignatureFactory.getSignatureScheme(currentType,
                      privateKey,
                      hashFunctionType.isProvablySecure());
                  int digestSize = hashFunctionType.getCustomSize() == null ? 0
                      : (int) Math.round((keyLength * hashFunctionType.getCustomSize()[0])
                          / (double) hashFunctionType.getCustomSize()[1]);
                  digestSize = Math.floorDiv(digestSize + 7, 8);
                  sigScheme.setDigest(hashFunctionType.getDigestType(), digestSize);

                  long startTime = System.nanoTime();
                  byte[] signature = sigScheme.sign(message.getBytes());
                  long endTime = System.nanoTime() - startTime;
                  byte[] nonRecoverableM = sigScheme.getNonRecoverableM();

                  // Store results
                  timesPerKey.get(actualKeyIndex).add(endTime);
                  signaturesPerKey.get(actualKeyIndex).add(signature);
                  nonRecoverableMessagesPerKey.get(actualKeyIndex).add(nonRecoverableM);

                  completedWork++;
                  double currentKeyProgress = (double) completedWork / totalWork;
                  progressUpdater.accept(currentKeyProgress);


                }
              }
            }
          }
        }
        messageCounter++;
      }

      // Combine results into final lists
      combineResultsIntoFinalLists(timesPerKey, signaturesPerKey,
          nonRecoverableMessagesPerKey);
    }
  }


  /**
   * Combines the results of batch signature creation into final lists for analysis and export in
   * comparison mode. It aggregates times, signatures, and non-recoverable message parts from all
   * keys.
   *
   * @param timesPerKey                  Times for each key.
   * @param signaturesPerKey             Signatures for each key.
   * @param nonRecoverableMessagesPerKey Non-recoverable message parts for each key.
   */
  void combineResultsIntoFinalLists(List<List<Long>> timesPerKey,
      List<List<byte[]>> signaturesPerKey,
      List<List<byte[]>> nonRecoverableMessagesPerKey) {

    // Calculating the total number of keys and keys per key size for iteration
    int totalKeys = keyBatch.size();
    int keysPerKeySize = totalKeys / numKeySizesForComparisonMode;
    int totalMessages = numTrials; // Total number of messages in a trial

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

          // Iterate for each hash function and through all messages for the current key
          for (int hashIndex = 0; hashIndex < numHashFunctions; hashIndex++) {
            for (int messageIndex = 0; messageIndex < totalMessages; messageIndex++) {
              // Calculate the result index based on message and hash function index
              int resultIndex = messageIndex * numHashFunctions + hashIndex;

              // Ensure index is within the bounds of the result list for the current key
              if (resultIndex < signaturesPerKey.get(actualKeyIndex).size()) {
                // Add results to the combined lists
                signaturesFromBenchmark.add(signaturesPerKey.get(actualKeyIndex).get(resultIndex));
                nonRecoverableMessages.add(
                    nonRecoverableMessagesPerKey.get(actualKeyIndex).get(resultIndex));
                clockTimesPerTrial.add(timesPerKey.get(actualKeyIndex).get(resultIndex));
              }
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
   * corresponding to each key configuration. The method updates the progress of signature
   * verification using the provided progressUpdater consumer.
   *
   * @param batchMessageFile   The file containing the messages to be verified.
   * @param batchSignatureFile The file containing the corresponding signatures to be verified.
   * @param progressUpdater    A consumer to update the progress of the batch verification process.
   * @throws IOException                   If there is an I/O error reading from the files.
   * @throws InvalidSignatureTypeException If the signature type is not supported.
   * @throws DataFormatException           If the data format is incorrect for verification.
   * @throws NoSuchAlgorithmException      If the specified algorithm does not exist.
   * @throws InvalidDigestException        If the specified digest algorithm is invalid.
   * @throws NoSuchProviderException       If the specified provider is not available.
   */
  public void batchVerifySignatures(File batchMessageFile, File batchSignatureFile,
      DoubleConsumer progressUpdater)
      throws IOException, InvalidSignatureTypeException, DataFormatException, NoSuchAlgorithmException, InvalidDigestException, NoSuchProviderException {

    this.messageFile = batchMessageFile;
    this.numKeySizesForComparisonMode = keyBatch.size() / numKeysPerKeySizeComparisonMode;
    setKeyLengths(keyBatch);

    // Initialise lists to store verification details for each key
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

    int totalKeys = keyBatch.size();
    int keysPerKeySize = totalKeys / numKeySizesForComparisonMode;
    int completedWork = 0;
    calculateTotalWork();

    // Read signatures from the batch signature file
    try (BufferedReader signatureReader = new BufferedReader(new FileReader(batchSignatureFile))) {
      // Iterate over each key size
      for (int keySizeIndex = 0; keySizeIndex < numKeySizesForComparisonMode; keySizeIndex++) {
        int keyOffset =
            keySizeIndex * keysPerKeySize; // Calculate key offset for the current key size

        // Iterate over each group of keys
        for (int groupIndex = 0; groupIndex < keyConfigToHashFunctionsMap.size(); groupIndex++) {
          List<HashFunctionSelection> hashFunctions = keyConfigToHashFunctionsMap.get(groupIndex);

          // Iterate over each key in the current group
          for (int keyIndex = 0; keyIndex < keysPerGroup; keyIndex++) {
            int actualKeyIndex = keyOffset + groupIndex * keysPerGroup + keyIndex;

            if (actualKeyIndex >= totalKeys) {
              break; // Skip if key index exceeds the total number of keys
            }

            // Get public key and signature scheme for the current key
            PublicKey publicKey = (PublicKey) keyBatch.get(actualKeyIndex);
            SigScheme sigScheme = SignatureFactory.getSignatureScheme(currentType, publicKey,
                hashFunctions.get(0).isProvablySecure());
            int keyLength = keyLengths.get(actualKeyIndex);
            int digestSize = hashFunctions.get(0).getCustomSize() == null ? 0 : (int) Math.round(
                (keyLength * hashFunctions.get(0).getCustomSize()[0]) / (double) hashFunctions.get(
                    0).getCustomSize()[1]);
            digestSize = Math.floorDiv(digestSize + 7, 8);

            // Iterate over each hash function used for the current key
            for (HashFunctionSelection hashFunction : hashFunctions) {
              sigScheme.setDigest(hashFunction.getDigestType(), digestSize);

              // Verify each message using the current key and hash function
              try (BufferedReader messageReader = new BufferedReader(
                  new FileReader(batchMessageFile))) {
                String messageLine;
                while ((messageLine = messageReader.readLine()) != null) {
                  String signatureLine = signatureReader.readLine();
                  byte[] signatureBytes = new BigInteger(signatureLine).toByteArray();

                  // Perform the signature verification and store the results
                  Pair<Boolean, Pair<Long, List<byte[]>>> result = getBatchVerificationResult(
                      sigScheme, messageLine, signatureBytes);
                  long endTime = result.getValue().getKey();

                  timesPerKey.get(actualKeyIndex).add(endTime);
                  verificationResultsPerKey.get(actualKeyIndex).add(result.getKey());
                  signaturesPerKey.get(actualKeyIndex).add(signatureBytes);
                  recoveredMessagesPerKey.get(actualKeyIndex)
                      .add(result.getValue().getValue().get(2));

                  // Update progress
                  completedWork++;
                  double currentKeyProgress = (double) completedWork / totalWork;
                  progressUpdater.accept(currentKeyProgress);
                }
              }
            }
          }
        }
      }
    }

    // Combine the results into final lists for further processing or analysis
    combineVerificationResultsIntoFinalLists(timesPerKey, verificationResultsPerKey,
        signaturesPerKey, recoveredMessagesPerKey);
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
   * Calculates the total amount of work (in terms of operations) that needs to be performed during
   * the signature creation/verification processes in the cross-parameter benchmarking/comparison
   * mode. This method considers the number of keys in each group, the number of hash functions
   * applied to each group, and the total number of trials and key sizes specified for the
   * benchmarking. Additionally, this method initialises and populates the 'trialsPerKeyByGroup'
   * array, which stores the number of trials to be conducted for each key in a given group.
   */
  public void calculateTotalWork() {
    trialsPerKeyByGroup = new int[totalGroups];
    for (int groupIndex = 0; groupIndex < totalGroups; groupIndex++) {
      List<HashFunctionSelection> hashFunctions = keyConfigToHashFunctionsMap.get(groupIndex);
      int numHashFunctionsInGroup = hashFunctions != null ? hashFunctions.size() : 0;
      totalWork += keysPerGroup * numHashFunctionsInGroup;
      trialsPerKeyByGroup[groupIndex] = numTrials * numHashFunctionsInGroup;
    }
    // Multiply by the number of trials
    totalWork = totalWork * numTrials * numKeySizesForComparisonMode;
  }


}
