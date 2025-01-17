package uk.msci.project.rsa;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.DataFormatException;

import uk.msci.project.rsa.exceptions.InvalidDigestException;
import uk.msci.project.rsa.SigScheme;
import uk.msci.project.rsa.Key;
import uk.msci.project.rsa.DigestType;

/**
 * This class implements the ANSI X9.31 RDSA signature scheme using RSA keys.
 * It provides
 * functionalities to sign and verify messages with RSA digital signatures,
 * generally conforming to
 * the ANSI X9.31 specification.
 */
public class ANSI_X9_31_RDSA extends SigScheme {

  private static final byte[] SHA_256_HASH_ID = new byte[]{(byte) 0x34,
    (byte) 0xCC};

  private static final byte[] SHA_512_HASH_ID = new byte[]{(byte) 0x35,
    (byte) 0xCC};

  private static final byte[] SHAKE_HASH_ID = new byte[]{(byte) 0x3D,
    (byte) 0xCC};


  /**
   * Constructs an ANSI X9.31 instance with the specified RSA key.
   * Initialises the modulus and
   * exponent from the key, calculates the encoded message length, and sets
   * up the SHA-256 message
   * digest along with a predefined hash ID.
   *
   * @param key The RSA key containing the exponent and modulus.
   */
  public ANSI_X9_31_RDSA(Key key) {
    super(key);
    this.hashID = SHA_256_HASH_ID;
    isRecoveryScheme = false;
  }

  /**
   * Retrieves the hash ID associated with a given digest type. This method
   * returns the predefined
   * hash ID byte array for the specified digest type as per the ISO/IEC
   * 10118 standard which
   * defines various dedicated hash functions referenced form ANSI X9.31
   * specification.
   *
   * @param digestType The type of digest algorithm for which the hash ID is
   *                   required.
   * @return A byte array representing the hash ID associated with the
   * specified digest type.
   * @throws IllegalArgumentException If the provided digest type is not
   * supported.
   */
  public byte[] getHashID(DigestType digestType) {
    return switch (digestType) {
      case SHA_256 -> SHA_256_HASH_ID;
      case SHA_512 -> SHA_512_HASH_ID;
      case SHAKE_128 -> SHAKE_HASH_ID;
      case SHAKE_256 -> SHAKE_HASH_ID;
      case MGF_1_SHA_256 -> SHA_256_HASH_ID;
      case MGF_1_SHA_512 -> SHA_512_HASH_ID;
    };
  }


  /**
   * Constructs an ANSI X9.31 instance with the specified RSA key and a flag
   * for using provably
   * secure parameters. It performs the same initialisations as the
   * single-argument constructor and
   * additionally sets the flag for using provably secure parameters in the
   * signature scheme.
   *
   * @param key                    The RSA key containing the exponent and
   *                               modulus.
   * @param isProvablySecureParams A boolean flag indicating if provably
   *                               secure parameters should be
   *                               used in the signature scheme.
   */
  public ANSI_X9_31_RDSA(Key key, boolean isProvablySecureParams) {
    super(key, isProvablySecureParams);
    this.hashID = SHA_256_HASH_ID;
  }


  /**
   * Encodes a message as per the ANSI X9.31 rDSA standard. Includes hashing
   * the message and
   * preparing the encoded message with padding. The format is: 0x06 ∥ 0xB..
   * .B ∥ 0xA ∥ H(m) ∥ hashID
   * where hashID is 16-bit.
   *
   * @param M The message to be encoded.
   * @return The encoded message as a byte array.
   */
  @Override

  protected byte[] encodeMessage(byte[] M) {
    byte[] EM = new byte[emLen];

    byte[] digestInfo = createDigestInfo(M);
    int tLen = digestInfo.length;
    int hashStart = emLen - tLen;
    System.arraycopy(digestInfo, 0, EM, hashStart, tLen);
    int delta = hashStart;

    // Pad with Bs to fill the remaining space
    if ((delta - 1) > 0) {
      for (int i = delta - 1; i != 0; i--) {
        EM[i] = (byte) 0xbb;
      }
      EM[delta - 1] ^= (byte) 0x01;
      EM[0] = (byte) 0x6B;
    } else {
      EM[0] = (byte) 0x6A;
    }
    return EM;
  }


  /**
   * Sets the message digest algorithm to be used for hashing in the ANSI X9
   * .31 RDSA signature
   * scheme to the specified digest type, with the option to specify a custom
   * hash size.
   *
   * @param digestType     The type of message digest algorithm to be set.
   * @param customHashSize The custom hash size, used only for
   *                       variable-length hash types.
   * @throws NoSuchAlgorithmException If the specified algorithm is not
   * available in the
   *                                  environment.
   * @throws InvalidDigestException   If the specified digest type is invalid
   * or unsupported.
   * @throws NoSuchProviderException  If the specified provider for the
   * algorithm is not available.
   * @throws IllegalArgumentException If the custom hash size is not a
   * positive integer that allows
   *                                  incorporation of minimum padding bytes.
   */
  @Override
  public void setDigest(DigestType digestType, int customHashSize)
    throws NoSuchAlgorithmException, InvalidDigestException,
    NoSuchProviderException {
    int availableSpace = customHashSize * 8 + 1 + 4 - emBits;
    if (availableSpace > 0) {
      throw new IllegalArgumentException(
        "Custom hash size must a positive integer that allows the minimum " +
          "bytes of padding to be incorporated");
    }
    super.setDigest(digestType, customHashSize);
  }


  /**
   * Creates a DigestInfo structure manually as per the ANSI X9.31 rDSA
   * standard by appending the
   * hash to the corresponding hash ID.
   *
   * @param message The message to be included in the DigestInfo, represented
   *               as a byte array.
   * @return A byte array representing the DigestInfo structure, including
   * the hash algorithm ID and
   * the computed hash (masked or standard) of the message.
   */
  public byte[] createDigestInfo(byte[] message) {
    byte[] mHash = computeHashWithOptionalMasking(message);
    byte[] digestInfo = new byte[this.hashSize + this.hashID.length];
    System.arraycopy(mHash, 0, digestInfo, 0, mHash.length);
    // Copy the hash ID into the digestInfo array, immediately after the hash.
    System.arraycopy(this.hashID, 0, digestInfo, this.hashSize,
      this.hashID.length);
    return digestInfo;
  }


}
