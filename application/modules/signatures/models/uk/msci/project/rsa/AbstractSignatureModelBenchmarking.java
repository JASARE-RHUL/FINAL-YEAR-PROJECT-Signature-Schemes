package uk.msci.project.rsa;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.function.DoubleConsumer;
import java.util.stream.Collectors;
import java.util.zip.DataFormatException;
import javafx.util.Pair;
import uk.msci.project.rsa.exceptions.InvalidDigestException;
import uk.msci.project.rsa.exceptions.InvalidSignatureTypeException;

/**
 * This class is part of the Model component specific to digital signature operations providing
 * methods to sign data and verify signatures.  It encapsulates the data and the logic required to
 * keep track of a user-initiated digital signature scheme.
 */
public abstract class AbstractSignatureModelBenchmarking extends SignatureModel {


  /**
   * A list that stores the clock times for each trial during batch signature generation. This is
   * useful for benchmarking the performance of the signature creation process.
   */
  List<Long> clockTimesPerTrial = new ArrayList<>();

  /**
   * A list to store the generated signatures from the benchmarking process. Each entry corresponds
   * to a signature generated for a message in the batch.
   */
  List<byte[]> signaturesFromBenchmark = new ArrayList<>();

  /**
   * A list to store the non-recoverable part of the messages from the signature generation process.
   * This is relevant for signature schemes that involve message recovery.
   */
  List<byte[]> nonRecoverableMessages = new ArrayList<>();

  /**
   * Stores the recoverable parts of messages from the verification process. This list is relevant
   * for signature schemes that involve message recovery.
   */
  List<byte[]> recoverableMessages = new ArrayList<>();


  /**
   * Stores the results of the verification process. Each boolean value in this list represents the
   * outcome of a verification trial.
   */
  List<Boolean> verificationResults = new ArrayList<>();


  /**
   * A batch of keys used for generating or verifying signatures in a benchmarking session.
   */
  List<Key> keyBatch = new ArrayList<>();

  /**
   * The number of trials to run in the benchmarking/batch methods. This determines how many
   * messages from the batch file are processed.
   */
  int numTrials = 0;

  /**
   * The message file to be processed during benchmarking.
   */
  File messageFile;

  /**
   * An array storing the fraction used to determine the custom hash size based on the key length.
   * The first element of the array represents the numerator, and the second element represents the
   * denominator of the fraction. This array is used in the calculation of custom hash sizes for
   * arbitrary length hash functions in signature operations.
   */
  int[] customHashSizeFraction;


  /**
   * A list storing the lengths of the keys in the current key batch in bits. This list is used to
   * keep track of key sizes.
   */
  List<Integer> keyLengths;

  /**
   * The total number of signature operations completed during the current benchmarking process.
   * This field tracks the progress of the batch signature creation and verification processes and
   * is used to update the progress indicator provided to the user.
   */
  int completedWork;


  /**
   * The total amount of work for the comparison mode benchmarking. It represents the total number
   * of signature operations that will be performed across all keys, hash functions, and trials.
   */
  int totalWork;


  /**
   * Clears all keys from the key batch.
   */
  public void clearKeyBatch() {
    keyBatch.clear();
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
   * Adds a key to the batch of keys maintained by the model used for batch operations in
   * benchmarking scenarios. Each key added can be utilised in subsequent operations that involve
   * processing multiple keys in a single session.
   *
   * @param key The key to be added to the batch. This key should conform to the requirements of the
   *            operations for which the batch is intended (e.g., it should be a private key for
   *            signature generation or a public key for signature verification).
   */
  public void addKeyToBatch(Key key) {
    keyBatch.add(key);
  }


  /**
   * Retrieves the number of keys in the current key batch.
   *
   * @return The size of the public key batch.
   */
  public int getKeyBatchLength() {
    return keyBatch.size();
  }


  abstract void batchCreateSignatures(File batchMessageFile, DoubleConsumer progressUpdater)
      throws InvalidSignatureTypeException, NoSuchAlgorithmException, InvalidDigestException, NoSuchProviderException, IOException, DataFormatException, ExecutionException, InterruptedException;

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

  abstract void batchVerifySignatures(File batchMessageFile, File batchSignatureFile,
      DoubleConsumer progressUpdater)
      throws IOException, InvalidSignatureTypeException, DataFormatException, NoSuchAlgorithmException, InvalidDigestException, NoSuchProviderException;

  /**
   * Performs a single verification of a signature against corresponding message using a given
   * signature scheme for utilisation during the batch verification process, where multiple messages
   * and their respective signatures are verified. It handles different types of signature schemes,
   * including those with message recovery capabilities.
   *
   * @param sigScheme      The signature scheme to be used for verification.
   * @param messageLine    The message (or non-recoverable part of the message in schemes with
   *                       message recovery) to be verified against the signature.
   * @param signatureBytes The byte array representing the signature to be verified.
   * @return A Pair object where the first element is a Boolean indicating the verification result
   * (true if verification succeeds, false otherwise), and the second element is a Pair consisting
   * of the verification duration (in nanoseconds) and a List of byte arrays. The List contains the
   * original message bytes, the signature bytes, and (if applicable) the recovered message bytes.
   * @throws DataFormatException if the data format is incorrect or incompatible with the specified
   *                             signature scheme.
   */
  Pair<Boolean, Pair<Long, List<byte[]>>> getBatchVerificationResult(SigScheme sigScheme,
      String messageLine, byte[] signatureBytes) throws DataFormatException {
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
   * @param digestSize     The size of the digest to be used in the verification process.
   * @return A Pair containing the result of verification and the relevant data (original message,
   * signature, and recovered message if applicable).
   * @throws InvalidSignatureTypeException If the signature type is invalid.
   * @throws DataFormatException           If the data format is incorrect.
   */
  Pair<Boolean, Pair<Long, List<byte[]>>> verifySignature(
      Key publicKey,
      String messageLine, byte[] signatureBytes, int digestSize)
      throws
      InvalidSignatureTypeException, DataFormatException, NoSuchAlgorithmException, InvalidDigestException, NoSuchProviderException {
    SigScheme sigScheme = SignatureFactory.getSignatureScheme(currentType, publicKey,
        isProvablySecure);
    sigScheme.setDigest(currentHashType, digestSize);
    return getBatchVerificationResult(sigScheme, messageLine, signatureBytes);
  }

  /**
   * Exports verification results to a CSV file for a specific key index ()benchmarking mode) or key
   * size index (comparison benchmarking). Each line in the file will contain the index of the key
   * used for verification, the verification result, the original message, the signature, and the
   * recovered message (if any).
   *
   * @param keyIndex        The index of the key/keySize for which verification results are
   *                        exported.
   * @param keySize         The length of the key/key size for which verification results are
   *                        exported.
   * @param progressUpdater A consumer to update the progress of the export process.
   * @throws IOException If there is an error writing to the file.
   */
  abstract void exportVerificationResultsToCSV(int keyIndex, int keySize,
      DoubleConsumer progressUpdater) throws IOException;

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
   * Computes the lengths of the keys in the provided batch in bits. This method is used to
   * determine the size of each key, which is essential for various cryptographic operations and
   * performance analysis. The length of each key is calculated based on the modulus bit length,
   * rounded to the nearest byte size.
   *
   * @param keyBatch A list of keys whose lengths are to be calculated. These keys are typically
   *                 used in batch operations like signature generation or verification.
   * @return A list of integers representing the length of each key in bits. This list is parallel
   * to the input list, meaning each index in the return list corresponds to the key at the same
   * index in the input list.
   */

  public List<Integer> computeKeyLengths(List<Key> keyBatch) {
    List<Integer> result = new ArrayList<>();
    for (Key key : keyBatch) {
      result.add(((key.getModulus().bitLength() + 7) / 8) * 8);
    }
    return result;
  }

  /**
   * Sets the list of key lengths based on the provided key batch. Each key's length is calculated
   * and stored in the 'keyLengths' list.
   *
   * @param keyBatch A list of keys whose lengths are to be calculated and stored.
   */
  public void setKeyLengths(List<Key> keyBatch) {
    keyLengths = computeKeyLengths(keyBatch);
  }

  /**
   * Retrieves the lengths of alls from the current key batch in bits. This method provides insight
   * into the strength of the keys used in the signature process.
   *
   * @return A list of integer values, each representing the bit length of a private key in the
   * batch.
   */
  public List<Integer> getKeyLengths() {
    return keyLengths;
  }


  /**
   * Sets the fraction used to calculate the custom hash size based on the key length. The array
   * should contain two elements: the first element represents the numerator, and the second element
   * represents the denominator of the fraction. This method is crucial for configuring the model to
   * use custom hash sizes for signature operations when a variable length hash function is
   * specified in benchmarking mode.
   *
   * @param customHashSizeFraction An array representing the fraction for custom hash size
   *                               calculation.
   */
  public void setCustomHashSizeFraction(int[] customHashSizeFraction) {
    this.customHashSizeFraction = customHashSizeFraction;
  }

  /**
   * Retrieves the fraction used to calculate the custom hash size based on provided key lengths in
   * normal benchmarking mode.
   *
   * @return corresponding fraction represented as an int list
   */
  public int[] getCustomHashSizeFraction() {
    return customHashSizeFraction;
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
  void combineVerificationResultsIntoFinalLists(List<List<Long>> timesPerKey,
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
  void combineResultsIntoFinalLists(List<List<Long>> timesPerKey,
      List<List<byte[]>> signaturesPerKey,
      List<List<byte[]>> nonRecoverableMessagesPerKey) {
  }


}
