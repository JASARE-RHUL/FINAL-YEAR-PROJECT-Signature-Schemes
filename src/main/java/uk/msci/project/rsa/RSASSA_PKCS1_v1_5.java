package uk.msci.project.rsa;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.zip.DataFormatException;

/**
 * This class implements the RSASSA-PKCS1-v1_5 signature scheme using RSA keys. It provides
 * functionalities to sign and verify messages with RSA digital signatures, conforming to the PKCS#1
 * v1.5 specification.
 */
public class RSASSA_PKCS1_v1_5 {

  /**
   * The exponent part of the RSA key.
   */
  private BigInteger exponent;

  /**
   * The modulus part of the RSA key.
   */
  private BigInteger modulus;

  /**
   * The bit length of the modulus minus one.
   */
  private int emBits;

  /**
   * The maximum message length in bytes.
   */
  private int emLen;

  /**
   * The RSA key containing the exponent and modulus.
   */
  private final Key key;

  /**
   * The MessageDigest instance used for hashing.
   */
  private MessageDigest md;


  /**
   * Constructs an RSASSA_PKCS1_v1_5 instance with the specified RSA key. Initialises the modulus
   * and exponent from the key, calculates the encoded message length, and sets up the SHA-256
   * message digest along with a predefined hash ID.
   *
   * @param key The RSA key containing the exponent and modulus.
   */
  public RSASSA_PKCS1_v1_5(Key key) {
    this.key = key;
    this.exponent = this.key.getExponent();
    this.modulus = this.key.getModulus();
    // emBits is the bit length of the modulus n, minus one.
    this.emBits = modulus.bitLength() - 1;
    // emLen is the maximum message length in bytes.
    this.emLen = (this.emBits + 7) / 8; // Convert bits to bytes and round up if necessary.
    // Initialize the MessageDigest with the hash function you plan to use.
    try {
      this.md = MessageDigest.getInstance("SHA-256");
    } catch (NoSuchAlgorithmException e) {
      // NoSuchAlgorithmException is a checked exception, RuntimeException allows an exception to
      // be thrown if the algorithm isn't available.
      throw new RuntimeException("SHA-256 algorithm not available", e);
    }

  }


  public byte[] EMSA_PKCS1_v1_5_ENCODE(byte[] M) throws DataFormatException {

    this.md.update(M);
    byte[] mHash = this.md.digest();
    // Calculate tLen, which is the length of the DigestInfo
    int tLen = mHash.length;

    // Prepare padding string PS consisting of padding bytes (0xFF).
    int psLength =
        this.emLen - tLen - 3; // Subtracting the prefix (0x00 || 0x01) and postfix (0x00) lengths
    byte[] PS = new byte[psLength];
    Arrays.fill(PS, (byte) 0xFF);

    // Concatenate PS, the DigestInfo, and other padding to form the encoded message EM.
    byte[] EM = new byte[this.emLen];
    int offset = 0;
    EM[offset++] = 0x00; // Initial 0x00
    EM[offset++] = 0x01; // Block type 0x01 for PKCS signatures
    System.arraycopy(PS, 0, EM, offset, psLength); // Padding
    offset += psLength;
    EM[offset++] = 0x00; // Separator
    System.arraycopy(mHash, 0, EM, offset, tLen);

    return EM;
  }

}





