package uk.msci.project.rsa;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.zip.DataFormatException;

/**
 * This class implements the ISO/IEC 9796-2 Scheme 1 signature scheme with full message recovery
 * using RSA keys. It provides functionalities for signing and verifying messages with RSA digital
 * signatures, conforming to the ISO/IEC 9796-2:2010 specification. This implementation recovers
 * part of the original message from the signature.
 */
public class ISO_IEC_9796_2_SCHEME_1_FR extends ISO_IEC_9796_2_SCHEME_1 {

  /**
   * Constructs an ISO_IEC_9796_2_SCHEME_FR instance with the specified RSA key. Initializes the
   * modulus and exponent from the key, sets up the SHA-256 message digest, and configures the
   * padding for partial message recovery.
   *
   * @param key The RSA key containing the exponent and modulus.
   */
  public ISO_IEC_9796_2_SCHEME_1_FR(Key key) {
    super(key, (byte) 0x40);
  }


  /**
   * In this implementation, the non-recoverable part of the message (m2) is not used, as the entire
   * message is recoverable (m1).
   *
   * @param M The non-recoverable part of the message (m2), not used in this scheme.
   */
  @Override
  public void addM2(byte[] M) {
  }


  /**
   * Generates a hash of the recoverable part of specified message M, which in this case (full
   * recovery) is the full message M.
   *
   * @param M  The full message.
   * @param M1 The recoverable part of the message.
   * @return A byte array representing the hash of M1 and M.
   */
  @Override
  public byte[] hashM1(byte[] M, byte[] M1) {
    return md.digest(M1);
  }

  /**
   * Verifies an RSA signature according to the ISO/IEC 9796-2 Scheme 1 standard. Validates the
   * encoded message structure, recovers the message, and checks the hash. In this case the full
   * message is recoverable so the non-recoverable portion is set to null.
   *
   * @param S The signature to be verified.
   * @return A SignatureRecovery object containing the result of the verification and any recovered
   * message.
   * @throws DataFormatException if the signature format is not valid.
   */
  public SignatureRecovery verifyMessageISO(byte[] S) throws DataFormatException {
    return super.verifyMessageISO(null, S);
  }

}



