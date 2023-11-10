package uk.msci.project.rsa;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.zip.DataFormatException;

/**
 * This class implements the RSASSA-PKCS1-v1_5 signature scheme using RSA keys. It provides
 * functionalities to sign and verify messages with RSA digital signatures, conforming to the PKCS#1
 * v1.5 specification.
 */
public class RSASSA_PKCS1_v1_5 extends SigScheme {

  /**
   * Constructs an RSASSA_PKCS1_v1_5 instance with the specified RSA key. Initialises the modulus
   * and exponent from the key, calculates the encoded message length, and sets up the SHA-256
   * message digest along with a predefined hash ID.
   *
   * @param key The RSA key containing the exponent and modulus.
   */
  public RSASSA_PKCS1_v1_5(Key key) {
    super(key);
  }

  /**
   * Signs the provided message using RSA private key operations. The method encodes the message,
   * generates a signature, and returns it as a byte array.
   *
   * @param M The message to be signed.
   * @return The RSA signature of the message.
   * @throws DataFormatException If the message encoding fails.
   */
  public byte[] sign(byte[] M) throws DataFormatException {
    byte[] EM = EMSA_PKCS1_v1_5_ENCODE(M);

    BigInteger m = OS2IP(EM);

    BigInteger s = RSASP1(m);

    byte[] S = I2OSP(s);

    // Output the signature S.
    return S;
  }


  /**
   * Encodes a message using a custom implementation of the EMSA-PKCS1-v1_5 encoding method.
   * Includes hashing the message and preparing the encoded message with padding.
   *
   * @param M The message to be encoded.
   * @return The encoded message as a byte array.
   */
  private byte[] EMSA_PKCS1_v1_5_ENCODE(byte[] M) throws DataFormatException {

    this.md.update(M);
    byte[] mHash = this.md.digest();

    byte[] digestInfo = createDigestInfo(mHash);
    int tLen = digestInfo.length;

    if (emLen < tLen + 11) { // 11 is the minimum padding length for PKCS#1 v1.5
      throw new DataFormatException("Intended encoded message length too short");
    }

    //Prepare padding string PS consisting of padding bytes (0xFF).
    int psLength =
        this.emLen - tLen - 3; // Subtracting the prefix (0x00 || 0x01) and postfix (0x00) lengths
    byte[] PS = new byte[psLength];
    Arrays.fill(PS, (byte) 0xFF);

    // Concatenate PS, the DigestInfo, and other padding to form the encoded message EM.
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
   * Creates a DigestInfo structure manually as per the PKCS#1 standard by pre-pending the hash
   * algorithm ID to a corresponding generated hash
   *
   * @param hash The hash of the message to be included in the DigestInfo.
   * @return A byte array representing the DigestInfo structure.
   */
  public byte[] createDigestInfo(byte[] hash) {
    byte[] digestInfo = new byte[this.hashID.length + hash.length];
    System.arraycopy(this.hashID, 0, digestInfo, 0, this.hashID.length);
    System.arraycopy(hash, 0, digestInfo, this.hashID.length, hash.length);
    return digestInfo;
  }

  /**
   * Verifies an RSA signature against a given message. Returns true if the signature is valid.
   *
   * @param M The original message.
   * @param S The RSA signature to be verified.
   * @return true if the signature is valid, false otherwise.
   * @throws DataFormatException If verification fails due to incorrect format.
   */
  public boolean verify(byte[] M, byte[] S) throws DataFormatException {
    return RSASSA_PKCS1_V1_5_VERIFY(M, S);
  }

  /**
   * A custom implementation of the RSASSA-PKCS1-v1_5 signature verification. Compares the encoded
   * message with the signature to determine if the signature is valid.
   *
   * @param M The original message that was signed.
   * @param S The signature to be verified.
   * @return true if the signature is valid; false otherwise.
   * @throws DataFormatException If verification fails due to formatting issues.
   */
  private boolean RSASSA_PKCS1_V1_5_VERIFY(byte[] M, byte[] S)
      throws DataFormatException {

    BigInteger s = OS2IP(S);

    BigInteger m = RSAVP1(s);

    byte[] EM = I2OSP(m);

    byte[] EMprime = EMSA_PKCS1_v1_5_ENCODE(M);

    return Arrays.equals(EM, EMprime);
  }

}





