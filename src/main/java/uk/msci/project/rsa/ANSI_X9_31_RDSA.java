package uk.msci.project.rsa;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.zip.DataFormatException;

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
    // hash ID for SHA-256 according the ANSI Specification
    this.hashID = new byte[]{(byte) 0x34, (byte) 0xCC};
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
  protected byte[] encodeMessage(byte[] M) throws DataFormatException {

    this.md.update(M);
    byte[] mHash = this.md.digest();

    byte[] digestInfo = createDigestInfo(mHash);
    int tLen = digestInfo.length;


    /*
    The non -repetitive part of the padding consists of the starting half - byte 0x6 (which
    is combined with the first 0xB to form 0x6B) and the ending half - byte 0xA (which is combined
    with the last 0xB to form 0xBA). Since these are combined into full bytes, they count as 2
    bytes in total.
     */

    // Calculate the length of the repeated 0xB padding
    int repeatedPadLength = emLen - tLen - 2;

    byte[] repeatedPad = new byte[repeatedPadLength];
    Arrays.fill(repeatedPad, (byte) 0xBB);

    byte[] EM = new byte[emLen];
    // Set the first byte to 0x6B
    EM[0] = (byte) 0x6B;

    // Copy the repeated padding into the EM array
    System.arraycopy(repeatedPad, 0, EM, 1, repeatedPadLength);

    // Set the last byte of padding to 0xBA
    EM[repeatedPadLength + 1] = (byte) 0xBA;

    // Copy the trailer into the EM array
    System.arraycopy(digestInfo, 0, EM, 2 + repeatedPadLength, tLen);

    return EM;
  }

  /**
   * Creates a DigestInfo structure manually as per the ANSI X9.31 rDSA standard standard by
   * appending the hash to the corresponding hash ID
   *
   * @param hash The hash of the message to be included in the DigestInfo.
   * @return A byte array representing the DigestInfo structure.
   */
  public byte[] createDigestInfo(byte[] hash) {
    //ordering swapped as compared to PKCS
    byte[] digestInfo = new byte[hash.length + this.hashID.length];
    System.arraycopy(hash, 0, digestInfo, 0, hash.length);
    System.arraycopy(this.hashID, 0, digestInfo, hash.length, this.hashID.length);
    return digestInfo;
  }

}





