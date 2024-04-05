package uk.msci.project.rsa;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.zip.DataFormatException;

import uk.msci.project.rsa.exceptions.InvalidDigestException;
import uk.msci.project.rsa.SigScheme;
import uk.msci.project.rsa.Key;
import uk.msci.project.rsa.DigestType;

/**
 * This class implements the RSASSA-PKCS1-v1_5 signature scheme using RSA
 * keys. It provides
 * functionalities to sign and verify messages with RSA digital signatures,
 * conforming to the PKCS#1
 * v1.5 specification.
 */
public class RSASSA_PKCS1_v1_5 extends SigScheme {

  private static final byte[] SHA_256_HASH_ID = new byte[]{(byte) 0x30,
    (byte) 0x31, (byte) 0x30,
    (byte) 0x0d, (byte) 0x06,
    (byte) 0x09, (byte) 0x60, (byte) 0x86, (byte) 0x48, (byte) 0x01,
    (byte) 0x65, (byte) 0x03, (byte) 0x04, (byte) 0x02, (byte) 0x01,
    (byte) 0x05, (byte) 0x00, (byte) 0x04, (byte) 0x20};

  private static final byte[] SHA_512_HASH_ID = new byte[]{
    (byte) 0x30, (byte) 0x51, (byte) 0x30, (byte) 0x0D,
    (byte) 0x06, (byte) 0x09, (byte) 0x60, (byte) 0x86,
    (byte) 0x48, (byte) 0x01, (byte) 0x65, (byte) 0x03,
    (byte) 0x04, (byte) 0x02, (byte) 0x03, (byte) 0x05,
    (byte) 0x00, (byte) 0x04, (byte) 0x40};

  private static final byte[] SHAKE_128_HASH_ID = new byte[]{
    (byte) 0x30, (byte) 0x31, (byte) 0x30, (byte) 0x0D,
    (byte) 0x06, (byte) 0x09, (byte) 0x60, (byte) 0x86,
    (byte) 0x48, (byte) 0x01, (byte) 0x65, (byte) 0x03,
    (byte) 0x04, (byte) 0x02, (byte) 0x0B, (byte) 0x05,
    (byte) 0x00, (byte) 0x04,
    (byte) 0x20};

  private static final byte[] SHAKE_256_HASH_ID = new byte[]{
    (byte) 0x30, (byte) 0x51, (byte) 0x30, (byte) 0x0D,
    (byte) 0x06, (byte) 0x09, (byte) 0x60, (byte) 0x86,
    (byte) 0x48, (byte) 0x01, (byte) 0x65, (byte) 0x03,
    (byte) 0x04, (byte) 0x02, (byte) 0x0C, (byte) 0x05,
    (byte) 0x00, (byte) 0x04,
    (byte) 0x40};

  private static final byte[] MGF_1_SHA_256_HASH_ID = new byte[]{
    (byte) 0x30, (byte) 0x1A, (byte) 0x06, (byte) 0x08,
    (byte) 0x2A, (byte) 0x86, (byte) 0x48, (byte) 0x86,
    (byte) 0xF7, (byte) 0x0D, (byte) 0x01, (byte) 0x01,
    (byte) 0x08, (byte) 0x30, (byte) 0x0D, (byte) 0x06,
    (byte) 0x09, (byte) 0x60, (byte) 0x86, (byte) 0x48,
    (byte) 0x01, (byte) 0x65, (byte) 0x03, (byte) 0x04,
    (byte) 0x02, (byte) 0x01, (byte) 0x05, (byte) 0x00
  };

  private static final byte[] MGF_1_SHA_512_HASH_ID = new byte[]{
    (byte) 0x30, (byte) 0x1A,
    (byte) 0x06, (byte) 0x08, (byte) 0x2A, (byte) 0x86, (byte) 0x48,
    (byte) 0x86, (byte) 0xF7,
    (byte) 0x0D, (byte) 0x01, (byte) 0x01, (byte) 0x08,
    (byte) 0x30, (byte) 0x0D,
    (byte) 0x06, (byte) 0x09, (byte) 0x60, (byte) 0x86, (byte) 0x48,
    (byte) 0x01, (byte) 0x65,
    (byte) 0x03, (byte) 0x04, (byte) 0x02, (byte) 0x03, (byte) 0x05, (byte) 0x00
  };


  /**
   * Constructs an RSASSA_PKCS1_v1_5 instance with the specified RSA key.
   * Initialises the modulus
   * and exponent from the key, calculates the encoded message length, and
   * sets up the SHA-256
   * message digest along with a predefined hash ID.
   *
   * @param key The RSA key containing the exponent and modulus.
   */
  public RSASSA_PKCS1_v1_5(Key key) {
    super(key);
    this.hashID = SHA_256_HASH_ID;
    isRecoveryScheme = false;
  }


  /**
   * Constructs an RSASSA_PKCS1_v1_5 instance with the specified RSA key and
   * a flag for using
   * provably secure parameters. It performs the same initialisations as the
   * single-argument
   * constructor and additionally sets the flag for using provably secure
   * parameters in the
   * signature scheme.
   *
   * @param key                    The RSA key containing the exponent and
   *                               modulus.
   * @param isProvablySecureParams A boolean flag indicating if provably
   *                               secure parameters should be
   *                               used in the signature scheme.
   */
  public RSASSA_PKCS1_v1_5(Key key, boolean isProvablySecureParams) {
    super(key, isProvablySecureParams);
    this.hashID = SHA_256_HASH_ID;
  }


  /**
   * Retrieves the hash ID associated with a given digest type. This method
   * returns the predefined
   * hash ID byte array for the specified digest type as per the PKCS#1 v1.5
   * specification.
   *
   * @param digestType The type of digest algorithm for which the hash ID is
   *                   required.
   * @return A byte array representing the hash ID associated with the
   * specified digest type.
   * @throws IllegalArgumentException If the provided digest type is not
   *                                  supported.
   */
  public byte[] getHashID(DigestType digestType) {
    return switch (digestType) {
      case SHA_256 -> SHA_256_HASH_ID;
      case SHA_512 -> SHA_512_HASH_ID;
      case SHAKE_128 -> SHAKE_128_HASH_ID;
      case SHAKE_256 -> SHAKE_256_HASH_ID;
      case MGF_1_SHA_256 -> MGF_1_SHA_256_HASH_ID;
      case MGF_1_SHA_512 -> MGF_1_SHA_512_HASH_ID;
    };
  }

  /**
   * Encodes a message using a custom implementation of the EMSA-PKCS1-v1_5
   * encoding method designed
   * to account for standard or provably secure parameters. Includes hashing
   * the message and
   * preparing the encoded message with padding.
   *
   * @param M The message to be encoded.
   * @return The encoded message as a byte array.
   * @throws DataFormatException If the message encoding fails.
   */
  @Override
  protected byte[] encodeMessage(byte[] M) throws DataFormatException {
    byte[] digestInfo = createDigestInfo(M);
    int tLen = digestInfo.length;

    if (emLen < tLen + 11) { // 11 is the minimum padding length for PKCS#1 v1.5
      throw new DataFormatException("Intended encoded message length too " +
        "short");
    }

    //Prepare padding string PS consisting of padding bytes (0xFF).
    int psLength =
      this.emLen - tLen - 3; // Subtracting the prefix (0x00 || 0x01) and
    // postfix (0x00) lengths
    byte[] PS = new byte[psLength];
    Arrays.fill(PS, (byte) 0xFF);

    // Concatenate PS, the DigestInfo, and other padding to form the encoded
    // message EM.
    byte[] EM = new byte[emLen];
    int offset = 0;
    EM[offset++] = 0x00; // Initial 0x00
    EM[offset++] = 0x01; // Block type 0x01 for PKCS signatures
    System.arraycopy(PS, 0, EM, offset, psLength); // Padding
    offset += psLength;
    EM[offset++] = 0x00; // Separator
    System.arraycopy(digestInfo, 0, EM, offset, tLen); // DigestInfo

    return EM;
  }


  /**
   * Sets the message digest algorithm to be used for hashing in the
   * RSASSA_PKCS1_v1_5 signature
   * scheme to the specified digest type, with the option to specify a custom
   * hash size.
   *
   * @param digestType     The type of message digest algorithm to be set.
   * @param customHashSize The custom hash size, used only for
   *                       variable-length hash types.
   * @throws NoSuchAlgorithmException If the specified algorithm is not
   *                                  available in the
   *                                  environment.
   * @throws InvalidDigestException   If the specified digest type is invalid
   *                                  or unsupported.
   * @throws NoSuchProviderException  If the specified provider for the
   *                                  algorithm is not available.
   * @throws IllegalArgumentException If the custom hash size is not a
   *                                  positive integer that allows
   *                                  incorporation of minimum padding bytes.
   */
  @Override
  public void setDigest(DigestType digestType, int customHashSize)
    throws NoSuchAlgorithmException, InvalidDigestException,
    NoSuchProviderException {
    int availableSpace = emLen - 11;
    if (customHashSize > availableSpace) {
      throw new IllegalArgumentException(
        "Custom hash size must a positive integer that allows the minimum " +
          "bytes of padding to be incorporated");
    }
    super.setDigest(digestType, customHashSize);
  }

  /**
   * Creates a DigestInfo structure manually as per the PKCS#1 standard by
   * pre-pending the hash
   * algorithm ID to the corresponding generated hash.
   *
   * @param message The message to be included in the DigestInfo, represented
   *                as a byte array.
   * @return A byte array representing the DigestInfo structure, including
   * the hash algorithm ID and
   * the computed hash (masked or standard) of the message.
   */
  public byte[] createDigestInfo(byte[] message) {
    byte[] mHash = computeHashWithOptionalMasking(message);
    byte[] digestInfo = new byte[this.hashSize + this.hashID.length];

    System.arraycopy(this.hashID, 0, digestInfo, 0, this.hashID.length);
    System.arraycopy(mHash, 0, digestInfo, this.hashID.length, mHash.length);

    return digestInfo;
  }

}
