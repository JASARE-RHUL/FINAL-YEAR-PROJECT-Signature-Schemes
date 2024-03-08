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
      // Initialise lists to store times and results (signatures and non-recoverable parts) for each key
      List<List<Long>> timesPerKey = new ArrayList<>();
      List<List<byte[]>> signaturesPerKey = new ArrayList<>();
      List<List<byte[]>> nonRecoverableMessagesPerKey = new ArrayList<>();
      setKeyLengths(keyBatch);

      for (int k = 0; k < keyBatch.size(); k++) {
        timesPerKey.add(new ArrayList<>());
        signaturesPerKey.add(new ArrayList<>());
        nonRecoverableMessagesPerKey.add(new ArrayList<>());
      }

      String message;
      int totalWork = numTrials * keyBatch.size();
      int completedWork = 0;
      int messageCounter = 0;
      while ((message = messageReader.readLine()) != null && messageCounter < this.numTrials) {
        int keyIndex = 0;
        for (Key key : keyBatch) {
          if (key instanceof PrivateKey privateKey) {
            int keyLength = keyLengths.get(keyIndex);
            int digestSize = customHashSizeFraction == null ? 0
                : (int) Math.round((keyLength * customHashSizeFraction[0])
                    / (double) customHashSizeFraction[1]);
            digestSize = Math.floorDiv(digestSize + 7, 8);

            // Synchronous signature creation
            SigScheme sigScheme = SignatureFactory.getSignatureScheme(currentType, privateKey,
                isProvablySecure);
            sigScheme.setDigest(currentHashType, digestSize);
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
        }
        messageCounter++;
      }

      // Combine results into final lists
      combineResultsIntoFinalLists(timesPerKey, signaturesPerKey,
          nonRecoverableMessagesPerKey);
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
    setKeyLengths(keyBatch);
    for (int k = 0; k < keyBatch.size(); k++) {
      timesPerKey.add(new ArrayList<>());
      verificationResultsPerKey.add(new ArrayList<>());
      signaturesPerKey.add(new ArrayList<>());
      recoveredMessagesPerKey.add(new ArrayList<>());
    }

    try (BufferedReader signatureReader = new BufferedReader(new FileReader(batchSignatureFile));
        BufferedReader messageReader = new BufferedReader(new FileReader(batchMessageFile))) {

      String messageLine;
      int messageCounter = 0;
      int totalWork = numTrials * keyBatch.size();
      int completedWork = 0;
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

            // Synchronous verification
            Pair<Boolean, Pair<Long, List<byte[]>>> result = verifySignature(publicKey, messageLine,
                signatureBytes, digestSize);

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
        }
        messageCounter++;
      }

      // Combine results into final lists
      combineVerificationResultsIntoFinalLists(timesPerKey, verificationResultsPerKey,
          signaturesPerKey, recoveredMessagesPerKey);
    }
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
  public void combineVerificationResultsIntoFinalLists(List<List<Long>> timesPerKey,
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

    for (int msgIndex = 0; msgIndex < this.numTrials; msgIndex++) {
      for (int keyIndex = 0; keyIndex < keyBatch.size(); keyIndex++) {
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
        "verificationResults_" + getKeyLengths().get(keyIndex) + "bits.csv");

    try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
      // Write header
      writer.write(
          "KeyIndex" + " (" + getKeyLengths().get(keyIndex) + "bit), "
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


}
