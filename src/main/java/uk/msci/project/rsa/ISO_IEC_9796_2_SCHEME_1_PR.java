package uk.msci.project.rsa;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.zip.DataFormatException;

/**
 * This class implements the ISO/IEC 9796-2 Scheme 1 signature scheme with partial message recovery
 * using RSA keys. It provides functionalities for signing and verifying messages with RSA digital
 * signatures, conforming to the ISO/IEC 9796-2:2010 specification. This implementation recovers
 * part of the original message from the signature.
 */
public class ISO_IEC_9796_2_SCHEME_1_PR extends ISO_IEC_9796_2_SCHEME_1 {

  /**
   * Constructs an ISO_IEC_9796_2_SCHEME_PR instance with the specified RSA key. Initializes the
   * modulus and exponent from the key, sets up the SHA-256 message digest, and configures the
   * padding for partial message recovery.
   *
   * @param key The RSA key containing the exponent and modulus.
   */
  public ISO_IEC_9796_2_SCHEME_1_PR(Key key) {
    super(key, (byte) 0x60);
  }


  /**
   * Processes and adds the non-recoverable part of the message (m2) to the message digest. This is
   * part of the message that is not covered by the signature.
   *
   * @param m2 The non-recoverable part of the message (m2).
   */
  public void addM2(byte[] m2) {
    if (m2 != null && m2.length > 0) {
      md.update(m2);
    }
  }

  /**
   * Generates a hash of the full message M, to enable later comparison with the concatenation of
   * the recoverable part of the message M1 (emLen - hashSize - 3 most significant bytes of M) and
   * the remaining non-recoverable part M2.
   *
   * @param M  The full message.
   * @param M1 The recoverable part of the message.
   * @return A byte array representing the hash of M1 and M.
   */
  @Override
  public byte[] hashM1(byte[] M, byte[] M1) {
    m2Len = Math.max(0, m1Len - availableSpace);
    return md.digest(M);
  }

  /**
   * Creates a signature for specified message and returns it along with the extracted
   * non-recoverable part of the message.
   *
   * @param M The message to be signed.
   * @return A 2D byte array where the first element is the signature and the second element is the
   * non-recoverable part of the message.
   * @throws DataFormatException If there is an error in data format during the signing process.
   */
  public byte[][] extendedSign(byte[] M) throws DataFormatException {
    byte[] S = super.sign(M);
    // Extract m2 from the original message M using the computed m2's length
    byte[] m2;
    if (m2Len > 0) {
      m2 = Arrays.copyOfRange(M, m1Len - m2Len - 1, m1Len);
    } else {
      // If m2Length is 0, then m2 is empty
      m2 = new byte[0];
    }
    return new byte[][]{S, m2};
  }

}



