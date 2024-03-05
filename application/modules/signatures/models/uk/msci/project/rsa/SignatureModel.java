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
import java.util.stream.Collectors;
import java.util.zip.DataFormatException;
import javafx.util.Pair;
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
   * @throws InvalidSignatureTypeException if the signature type is not supported.
   * @throws NoSuchAlgorithmException      if the specified algorithm does not exist.
   * @throws InvalidDigestException        if the specified digest algorithm is invalid.
   * @throws NoSuchProviderException       if the specified provider is not available.
   * @throws IOException                   if there is an I/O error reading from the
   *                                       batchMessageFile.
   * @throws DataFormatException           if the data format is incorrect for signing.
   */
  public void batchCreateSignatures(File batchMessageFile, DoubleConsumer progressUpdater)
      throws InvalidSignatureTypeException, NoSuchAlgorithmException, InvalidDigestException, NoSuchProviderException, IOException, DataFormatException {
    try (BufferedReader messageReader = new BufferedReader(new FileReader(batchMessageFile))) {
      this.messageFile = batchMessageFile;
      // Initialize lists to store times and results (signatures and non-recoverable parts) for each key
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

          // Synchronous signature creation
          SigScheme sigScheme = SignatureFactory.getSignatureScheme(currentType, key,
              isProvablySecure);
          sigScheme.setDigest(currentHashType, hashSize);
          long startTime = System.nanoTime();
          byte[] signature = sigScheme.sign(message.getBytes());
          long endTime = System.nanoTime() - startTime;
          byte[] nonRecoverableM = sigScheme.getNonRecoverableM();

          // Store results
          timesPerKey.get(keyIndex).add(endTime);
          signaturesPerKey.get(keyIndex).add(signature);
          nonRecoverableMessagesPerKey.get(keyIndex).add(nonRecoverableM);

          // Update progress
          double currentKeyProgress = (double) (++completedWork) / totalWork;
          progressUpdater.accept(currentKeyProgress);
          keyIndex++;
        }
        messageCounter++;
      }

      // Combine results into final lists
      combineResultsIntoFinalLists(timesPerKey, signaturesPerKey,
          nonRecoverableMessagesPerKey);
    }
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
  public void batchGenerateSignatures_ComparisonMode(File batchMessageFile,
      DoubleConsumer progressUpdater)
      throws InvalidSignatureTypeException, NoSuchAlgorithmException, InvalidDigestException, NoSuchProviderException, IOException, DataFormatException {

    this.messageFile = batchMessageFile;
    this.numKeySizesForComparisonMode = privKeyBatch.size() / numKeysPerKeySizeComparisonMode;

    try (BufferedReader messageReader = new BufferedReader(new FileReader(batchMessageFile))) {
      // Initialize lists to store times and results for each key
      List<List<Long>> timesPerKey = new ArrayList<>();
      List<List<byte[]>> signaturesPerKey = new ArrayList<>();
      List<List<byte[]>> nonRecoverableMessagesPerKey = new ArrayList<>();

      for (int k = 0; k < privKeyBatch.size(); k++) {
        timesPerKey.add(new ArrayList<>());
        signaturesPerKey.add(new ArrayList<>());
        nonRecoverableMessagesPerKey.add(new ArrayList<>());
      }

      String message;

      int completedWork = 0;

      int averageHashFunctionsPerKey = totalHashFunctions / keyConfigToHashFunctionsMap.size();

      int totalWork = numTrials * privKeyBatch.size() * averageHashFunctionsPerKey;

      int messageCounter = 0;

      while ((message = messageReader.readLine()) != null && messageCounter < this.numTrials) {
        for (int i = 0; i < privKeyBatch.size(); i += numKeysPerKeySizeComparisonMode) {
          for (int keyGroupIndex = 0; keyGroupIndex < numKeysPerKeySizeComparisonMode;
              keyGroupIndex += keysPerGroup) {
            List<HashFunctionSelection> hashFunctionTypesForGroup = keyConfigToHashFunctionsMap.get(
                keyGroupIndex / keysPerGroup);

            if (hashFunctionTypesForGroup != null) {
              for (HashFunctionSelection hashFunctionType : hashFunctionTypesForGroup) {
                for (int j = keyGroupIndex;
                    j < keyGroupIndex + keysPerGroup && j < numKeysPerKeySizeComparisonMode; j++) {
                  int actualKeyIndex = i + j;
                  PrivateKey privateKey = privKeyBatch.get(actualKeyIndex);
                  int keyLength = getPrivKeyLengths().get(actualKeyIndex);
                  SigScheme sigScheme = SignatureFactory.getSignatureScheme(currentType, privateKey,
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
      combineResultsIntoFinalListsComparisonMode(timesPerKey, signaturesPerKey,
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
  private void combineResultsIntoFinalListsComparisonMode(List<List<Long>> timesPerKey,
      List<List<byte[]>> signaturesPerKey,
      List<List<byte[]>> nonRecoverableMessagesPerKey) {

    int totalGroups = keyConfigToHashFunctionsMap.size();

    for (int keyIndex = 0; keyIndex < privKeyBatch.size(); keyIndex++) {
      int groupIndex = (keyIndex / keysPerGroup) % totalGroups;
      List<HashFunctionSelection> hashFunctionsForCurrentKey = keyConfigToHashFunctionsMap.get(
          groupIndex);

      for (int hashIndex = 0; hashIndex < hashFunctionsForCurrentKey.size(); hashIndex++) {
        for (int msgIndex = 0; msgIndex < this.numTrials; msgIndex++) {
          int resultIndex = msgIndex * hashFunctionsForCurrentKey.size() + hashIndex;

          signaturesFromBenchmark.add(signaturesPerKey.get(keyIndex).get(resultIndex));
          nonRecoverableMessages.add(nonRecoverableMessagesPerKey.get(keyIndex).get(resultIndex));
          clockTimesPerTrial.add(timesPerKey.get(keyIndex).get(resultIndex));
        }
      }
    }
    calculateTrialsPerKeyByGroup();
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
   * the signatures using the public keys in the batch. This method updates the progress of the
   * verification process using the progressUpdater consumer.
   *
   * @param batchMessageFile   The file containing the messages to be verified.
   * @param batchSignatureFile The file containing the corresponding signatures to be verified.
   * @param progressUpdater    A consumer to update the progress of the batch verification process.
   * @throws InvalidSignatureTypeException if the signature type is not supported.
   * @throws NoSuchAlgorithmException      if the specified algorithm does not exist.
   * @throws InvalidDigestException        if the specified digest algorithm is invalid.
   * @throws NoSuchProviderException       if the specified provider is not available.
   * @throws IOException                   if there is an I/O error reading from the
   *                                       batchMessageFile.
   * @throws DataFormatException           if the data format is incorrect for signing.
   */
  public void batchVerifySignatures(File batchMessageFile, File batchSignatureFile,
      DoubleConsumer progressUpdater)
      throws
      IOException, InvalidSignatureTypeException, DataFormatException, NoSuchAlgorithmException, InvalidDigestException, NoSuchProviderException {
    this.messageFile = batchMessageFile;
    // Initialise lists to store times, verification results, signatures, and recovered messages
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
          // Read signature for each message
          String signatureLine = signatureReader.readLine();
          byte[] signatureBytes = new BigInteger(signatureLine).toByteArray();

          // Synchronous verification
          Pair<Boolean, Pair<Long, List<byte[]>>> result = verifySignature(key, messageLine,
              signatureBytes);

          long endTime = result.getValue().getKey();

          // Store results
          timesPerKey.get(keyIndex).add(endTime);
          verificationResultsPerKey.get(keyIndex).add(result.getKey());
          signaturesPerKey.get(keyIndex).add(result.getValue().getValue().get(1));
          recoveredMessagesPerKey.get(keyIndex).add(result.getValue().getValue().get(2));

          // Update progress
          double currentKeyProgress = (double) (++completedWork) / totalWork;
          progressUpdater.accept(currentKeyProgress);

          keyIndex++;
        }
        messageCounter++;
      }

      // Combine results into final lists
      combineVerificationResultsIntoFinalLists(timesPerKey, verificationResultsPerKey,
          signaturesPerKey, recoveredMessagesPerKey);
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
  public void batchVerifySignatures_ComparisonMode(File batchMessageFile, File batchSignatureFile,
      DoubleConsumer progressUpdater)
      throws IOException, InvalidSignatureTypeException, DataFormatException, NoSuchAlgorithmException, InvalidDigestException, NoSuchProviderException {

    this.messageFile = batchMessageFile;
    this.numKeySizesForComparisonMode = publicKeyBatch.size() / numKeysPerKeySizeComparisonMode;
    // Initialize lists to store times, verification results, signatures, and recovered messages
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

      int averageHashFunctionsPerKey = totalHashFunctions / keyConfigToHashFunctionsMap.size();
      int completedWork = 0;

      int totalWork = numTrials * publicKeyBatch.size() * averageHashFunctionsPerKey;

      while ((messageLine = messageReader.readLine()) != null && messageCounter < this.numTrials) {
        for (int i = 0; i < publicKeyBatch.size(); i += numKeysPerKeySizeComparisonMode) {
          for (int keyGroupIndex = 0; keyGroupIndex < numKeysPerKeySizeComparisonMode;
              keyGroupIndex += keysPerGroup) {

            List<HashFunctionSelection> hashFunctionTypesForGroup = keyConfigToHashFunctionsMap.get(
                keyGroupIndex / keysPerGroup);

            if (hashFunctionTypesForGroup != null) {
              for (HashFunctionSelection hashFunctionType : hashFunctionTypesForGroup) {
                for (int j = keyGroupIndex;
                    j < keyGroupIndex + keysPerGroup && j < numKeysPerKeySizeComparisonMode; j++) {
                  int actualKeyIndex = i + j;

                  // Read signature for each message
                  String signatureLine = signatureReader.readLine();
                  byte[] signatureBytes = new BigInteger(signatureLine).toByteArray();

                  PublicKey publicKey = publicKeyBatch.get(actualKeyIndex);
                  SigScheme sigScheme = SignatureFactory.getSignatureScheme(currentType, publicKey,
                      hashFunctionType.isProvablySecure());
                  int keyLength = getPrivKeyLengths().get(actualKeyIndex);
                  int digestSize = hashFunctionType.getCustomSize() == null ? 0
                      : (int) Math.round((keyLength * hashFunctionType.getCustomSize()[0])
                          / (double) hashFunctionType.getCustomSize()[1]);
                  digestSize = Math.floorDiv(digestSize + 7, 8);
                  sigScheme.setDigest(hashFunctionType.getDigestType(), digestSize);
                  // Synchronous verification
                  Pair<Boolean, Pair<Long, List<byte[]>>> result = verifySignature_ComparisonMode(
                      sigScheme, messageLine, signatureBytes);

                  long endTime = result.getValue().getKey();

                  // Store results
                  timesPerKey.get(actualKeyIndex).add(endTime);
                  verificationResultsPerKey.get(actualKeyIndex).add(result.getKey());
                  signaturesPerKey.get(actualKeyIndex).add(signatureBytes);
                  recoveredMessagesPerKey.get(actualKeyIndex)
                      .add(result.getValue().getValue().get(2));

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
      combineVerificationResultsIntoFinalListsComparisonMode(timesPerKey, verificationResultsPerKey,
          signaturesPerKey, recoveredMessagesPerKey);
    }
  }

  /**
   * Verifies a signature against a message using a specified signature scheme in the comparison
   * mode. This method encapsulates the logic for signature verification, handling different types
   * of signature schemes, including those with message recovery. It accommodates the alternation
   * between standard and provably secure modes for each key size in the comparison mode.
   *
   * @param sigScheme      The signature scheme used for verification.
   * @param messageLine    The message to be verified against the signature.
   * @param signatureBytes The signature to be verified.
   * @return A Pair containing the result of verification and the relevant data (original message,
   * signature, and recovered message if applicable).
   */
  private Pair<Boolean, Pair<Long, List<byte[]>>> verifySignature_ComparisonMode(
      SigScheme sigScheme,
      String messageLine, byte[] signatureBytes)
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
        new Pair<>(endTime, List.of(messageLine.getBytes(), signatureBytes, recoveredMessage)));
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
  private Pair<Boolean, Pair<Long, List<byte[]>>> verifySignature(
      PublicKey publicKey,
      String messageLine, byte[] signatureBytes)
      throws
      InvalidSignatureTypeException, DataFormatException, NoSuchAlgorithmException, InvalidDigestException, NoSuchProviderException {
    SigScheme sigScheme = SignatureFactory.getSignatureScheme(currentType, publicKey,
        isProvablySecure);
    sigScheme.setDigest(currentHashType, hashSize);
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
        new Pair<>(endTime, List.of(messageLine.getBytes(), signatureBytes, recoveredMessage)));
  }


  /**
   * Aggregates the results of batch signature verification into final lists for analysis and export
   * in comparison mode. It combines verification results, signatures, and recovered messages from
   * each public key.
   *
   * @param timesPerKey               Times for each public key.
   * @param verificationResultsPerKey Verification results for each public key.
   * @param signaturesPerKey          Signatures for each public key.
   * @param recoveredMessagesPerKey   Recovered messages for each public key.
   */
  private void combineVerificationResultsIntoFinalListsComparisonMode(List<List<Long>> timesPerKey,
      List<List<Boolean>> verificationResultsPerKey,
      List<List<byte[]>> signaturesPerKey, List<List<byte[]>> recoveredMessagesPerKey) {

    verificationResults.clear();
    signaturesFromBenchmark.clear();
    recoverableMessages.clear();
    clockTimesPerTrial.clear();

    for (int keyIndex = 0; keyIndex < publicKeyBatch.size(); keyIndex++) {
      List<HashFunctionSelection> hashFunctionsForCurrentKey = keyConfigToHashFunctionsMap.get(
          keyIndex / keysPerGroup);

      for (int hashIndex = 0; hashIndex < hashFunctionsForCurrentKey.size(); hashIndex++) {
        for (int msgIndex = 0; msgIndex < this.numTrials; msgIndex++) {
          int resultIndex = msgIndex * hashFunctionsForCurrentKey.size() + hashIndex;

          verificationResults.add(verificationResultsPerKey.get(keyIndex).get(resultIndex));
          signaturesFromBenchmark.add(signaturesPerKey.get(keyIndex).get(resultIndex));
          recoverableMessages.add(recoveredMessagesPerKey.get(keyIndex).get(resultIndex));
          clockTimesPerTrial.add(timesPerKey.get(keyIndex).get(resultIndex));
        }
      }
    }
    calculateTrialsPerKeyByGroup();
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
          "KeyIndex" + " (" + getPublicKeyLengths().get(keyIndex) + "bit), "
              + "Verification Result, Original Message, Signature, Recovered Message\n");

      int numKeys = publicKeyBatch.size();
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
  void exportVerificationResultsToCSV_ComparisonMode(int keySizeIndex) throws IOException {
    File file = FileHandle.createUniqueFile(
        "verificationResults_ComparisonMode_" + getPublicKeyLengths().get(keySizeIndex)
            + "bits.csv");

    int currentIndex = 0;
    int headerStartIndex = 0; // Starting index for the row headers for each group
    try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
      // Write header
      writer.write(
          "Parameter Type" + " (" + getPublicKeyLengths().get(keySizeIndex)
              + "bit key), Hash Function, "
              + "Verification Result, Original Message, Signature, Recovered Message\n");
      while (currentIndex < clockTimesPerTrial.size()) {
        for (int groupIndex = 0; groupIndex < keyConfigToHashFunctionsMap.size(); groupIndex++) {
          List<HashFunctionSelection> hashFunctions = keyConfigToHashFunctionsMap.get(
              groupIndex);

          for (int hashFunctionIndex = 0; hashFunctionIndex < hashFunctions.size();
              hashFunctionIndex++) {
            for (int k = 0; k < keysPerGroup; k++) {
              int keyIndex = groupIndex * keysPerGroup + k;
              if (keyIndex >= publicKeyBatch.size()) {
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

  private void calculateTrialsPerKeyByGroup() {
    trialsPerKeyByGroup = new int[totalGroups];

    for (int groupIndex = 0; groupIndex < totalGroups; groupIndex++) {
      int numHashFunctionsInGroup = keyConfigToHashFunctionsMap.get(groupIndex).size();

      // Calculate the total number of trials for the current group
      int totalTrialsCurrentGroup =
          ((clockTimesPerTrial.size() / numKeySizesForComparisonMode) / totalHashFunctions)
              * numHashFunctionsInGroup;

      // Distribute these trials among the keys in the current group
      int totalTrialsPerKeyInGroup = totalTrialsCurrentGroup / keysPerGroup;

      trialsPerKeyByGroup[groupIndex] = totalTrialsPerKeyInGroup;
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
   * Retrieves the lengths of the keys in bits. This method is useful for identifying the strength
   * of the keys used in the signature process.
   *
   * @return A list of integer values, each representing the bit length of a key in the batch.
   */
  public List<Integer> getKeyLengths(List<? extends Key> keyBatch) {
    List<Integer> result = new ArrayList<>();
    for (Key key : keyBatch) {
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
    return getKeyLengths(privKeyBatch);
  }

  /**
   * Retrieves the lengths of the public keys in bits. This method is useful for identifying the
   * strength of the keys used in the signature process.
   *
   * @return A list of integer values, each representing the bit length of a public key in the
   * batch.
   */
  public List<Integer> getPublicKeyLengths() {
    return getKeyLengths(publicKeyBatch);
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
}
