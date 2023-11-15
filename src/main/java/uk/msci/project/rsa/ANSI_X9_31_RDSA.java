package uk.msci.project.rsa;

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
    // Assuming hashID is already set elsewhere to the correct value for SHA-256
    this.md.update(M);
    byte[] mHash = this.md.digest();


    int tLen = mHash.length + this.hashID.length;

    // Calculate the length of the padding 'BBBB...BBA'
    int psLen = emLen - tLen - 1; // Subtract 1 for the '6' at the beginning


    byte[] PS = new byte[psLen];

    Arrays.fill(PS, (byte) 0xBB);

    PS[psLen - 1] = (byte) 0xBA;

    byte[] EM = new byte[emLen];
    int pos = 0;

    // Set the first byte to '6'
    EM[pos++] = (byte) 0x06;

    // Copy the padding into the EM
    System.arraycopy(PS, 0, EM, pos, psLen);
    pos += psLen;
    byte[] digestInfo = createDigestInfo(mHash);


    System.arraycopy(digestInfo, 0, EM, pos, digestInfo.length);
    pos += digestInfo.length;

    return EM;
  }


  /**
   * Creates a DigestInfo structure manually as per the ANSI X9.31 rDSA standard by appending the
   * hash to the corresponding hash ID.
   *
   * @param hash The hash of the message to be included in the DigestInfo.
   * @return A byte array representing the DigestInfo structure.
   */
  public byte[] createDigestInfo(byte[] hash) {
    byte[] digestInfo = new byte[hash.length + this.hashID.length];

    System.arraycopy(hash, 0, digestInfo, 0, hash.length);

    // Copy the hash ID into the digestInfo array, immediately after the hash.
    System.arraycopy(this.hashID, 0, digestInfo, hash.length, this.hashID.length);

    return digestInfo;
  }


}





