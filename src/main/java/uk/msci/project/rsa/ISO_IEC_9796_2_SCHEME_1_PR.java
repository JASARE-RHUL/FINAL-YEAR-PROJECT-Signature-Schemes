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
   * Generates a hash of the full message M, to enable later be comparison with the concatenation of
   * the recoverable part of the message M1 (emLen - hashSize - 3 most significant bytes of M) and
   * remaining non-recoverable part M2.
   *
   * @param M  The full message.
   * @param M1 The recoverable part of the message.
   * @return A byte array representing the hash of M1 and M.
   */
  @Override
  public byte[] hashM1(byte[] M, byte[] M1) {
    return md.digest(M);
  }

}



