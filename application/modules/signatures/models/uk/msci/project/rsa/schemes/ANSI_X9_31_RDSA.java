package uk.msci.project.rsa;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.DataFormatException;
import uk.msci.project.rsa.exceptions.InvalidDigestException;

/**
 * This class implements the ANSI X9.31 RDSA signature scheme using RSA keys. It provides
 * functionalities to sign and verify messages with RSA digital signatures, generally conforming to
 * the ANSI X9.31 specification.
 */
public class ANSI_X9_31_RDSA extends SigScheme {

  /**
   * Constructs an ANSI X9.31 instance with the specified RSA key. Initialises the modulus and
   * exponent from the key, calculates the encoded message length, and sets up the SHA-256 message
   * digest along with a predefined hash ID.
   *
   * @param key The RSA key containing the exponent and modulus.
   */
  public ANSI_X9_31_RDSA(Key key) {
    super(key);
    initialiseHash();
  }


  /**
   * Constructs an ANSI X9.31 instance with the specified RSA key and a flag for using provably
   * secure parameters. It performs the same initialisations as the single-argument constructor and
   * additionally sets the flag for using provably secure parameters in the signature scheme.
   *
   * @param key                    The RSA key containing the exponent and modulus.
   * @param isProvablySecureParams A boolean flag indicating if provably secure parameters should be
   *                               used in the signature scheme.
   */
  public ANSI_X9_31_RDSA(Key key, boolean isProvablySecureParams) {
    super(key, isProvablySecureParams);
    initialiseHash();
  }

  /**
   * Initialises hash IDs for supported hash functions according to the Iso/Iec 10118
   */
  public void initialiseHash() {
    this.hashID = new byte[]{(byte) 0x34, (byte) 0xCC};
    byte[] sha512HashID = new byte[]{(byte) 0x35, (byte) 0xCC};
    hashIDmap.put(DigestType.SHA_256, this.hashID);
    hashIDmap.put(DigestType.SHA_512, sha512HashID);
    byte[] shakeHashID = new byte[]{(byte) 0x3D, (byte) 0xCC};
    hashIDmap.put(DigestType.SHAKE_128, shakeHashID);
    hashIDmap.put(DigestType.SHAKE_256, shakeHashID);
    hashIDmap.put(DigestType.MGF_1_SHA_256, this.hashID);
    hashIDmap.put(DigestType.MGF_1_SHA_512, sha512HashID);
  }


  /**
   * Encodes a message as per the ANSI X9.31 rDSA standard. Includes hashing the message and
   * preparing the encoded message with padding. The format is: 0x06 ∥ 0xB...B ∥ 0xA ∥ H(m) ∥ hashID
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
   * Sets the size of the hash used in the encoding process. If the hash function used is a
   * fixed-size hash, this method ensures that the hash size remains constant. If the hash function
   * supports variable-length output, the hash size is adjusted accordingly. If the flag for using
   * provably secure parameters is set to true, the hash size is set to half of the encoded message
   * length plus one byte. Otherwise, the hash size is set based on the specified value.
   *
   * @param hashSize The size of the hash in bytes. If set to 0, the method will use the digest
   *                 length of the current hash function.
   * @throws IllegalArgumentException If the specified hash size is negative or exceeds the
   *                                  available space for padding in the encoded message.
   */
  @Override
  public void setHashSize(int hashSize) {
    int availableSpace = ((emBits - (hashSize * 8) - 16 - 8) + 7) / 8;
    if (hashSize < 0 || availableSpace < 0) {
      throw new IllegalArgumentException(
          "Custom hash size must a positive integer that allows the minimum bytes of padding to be incorporated");
    }
    super.setHashSize(hashSize);
  }

  /**
   * Creates a DigestInfo structure manually as per the ANSI X9.31 rDSA standard by appending the
   * hash to the corresponding hash ID.
   *
   * @param message The message to be included in the DigestInfo, represented as a byte array.
   * @return A byte array representing the DigestInfo structure, including the hash algorithm ID and
   * the computed hash (masked or standard) of the message.
   */
  public byte[] createDigestInfo(byte[] message) {
    byte[] mHash = computeHashWithOptionalMasking(message);
    byte[] digestInfo = new byte[this.hashSize + this.hashID.length];
    System.arraycopy(mHash, 0, digestInfo, 0, mHash.length);
    // Copy the hash ID into the digestInfo array, immediately after the hash.
    System.arraycopy(this.hashID, 0, digestInfo, this.hashSize, this.hashID.length);
    return digestInfo;
  }


}
