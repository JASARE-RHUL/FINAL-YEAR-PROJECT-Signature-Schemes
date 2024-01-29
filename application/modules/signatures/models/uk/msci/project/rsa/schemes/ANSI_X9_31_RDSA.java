package uk.msci.project.rsa;

import java.security.NoSuchAlgorithmException;
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
   * Initialises hash IDs for supported hash functions (SHA-256 and SHA-512) according to the ANSI
   * X9.31 standard.
   */
  public void initialiseHash() {
    // hash IDs for supported hash functions according to the ANSI Specification
    this.hashID = new byte[]{(byte) 0x34, (byte) 0xCC};
    hashIDmap.put(DigestType.SHA_256, this.hashID);
    hashIDmap.put(DigestType.SHA_512, new byte[]{(byte) 0x35, (byte) 0xCC});
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
    //  int availableSpace = ((emBits - 48 - 8) + 7) / 8;
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
   * Creates a DigestInfo structure manually as per the ANSI X9.31 rDSA standard by appending the *
   * hash to the corresponding hash ID. This method applies a mask generation function (MGF1) to the
   * hash if the scheme is instantiated with the flag for provably secure parameters set, generating
   * a larger output (half the length of the modulus).
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
