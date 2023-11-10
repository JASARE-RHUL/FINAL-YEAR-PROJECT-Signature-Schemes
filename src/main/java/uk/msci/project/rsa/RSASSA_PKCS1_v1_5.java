package uk.msci.project.rsa;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
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
   * The identifier of the hash algorithm used.
   */
  private byte[] hashID;


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
      this.hashID = new byte[]{(byte) 0x30, (byte) 0x31, (byte) 0x30, (byte) 0x0d, (byte) 0x06,
          (byte) 0x09, (byte) 0x60, (byte) 0x86, (byte) 0x48, (byte) 0x01,
          (byte) 0x65, (byte) 0x03, (byte) 0x04, (byte) 0x02, (byte) 0x01,
          (byte) 0x05, (byte) 0x00, (byte) 0x04, (byte) 0x20};
    } catch (NoSuchAlgorithmException e) {
      // NoSuchAlgorithmException is a checked exception, RuntimeException allows an exception to
      // be thrown if the algorithm isn't available.
      throw new RuntimeException("SHA-256 algorithm not available", e);
    }

  }


  /**
   * Encodes a message using a custom implementation of the EMSA-PKCS1-v1_5 encoding method.
   * Includes hashing the message and preparing the encoded message with padding.
   *
   * @param M The message to be encoded.
   * @return The encoded message as a byte array.
   */
  public byte[] EMSA_PKCS1_v1_5_ENCODE(byte[] M) throws DataFormatException {

    this.md.update(M);
    byte[] mHash = this.md.digest();

    byte[] digestInfo = createDigestInfo(mHash);
    int tLen = digestInfo.length;

    if (emLen < tLen + 11) { // 11 is the minimum padding length for PKCS#1 v1.5
      throw new DataFormatException("Intended encoded message length too short");
    }

    //Prepare padding string PS consisting of padding bytes (0xFF).
    int psLength =
        emLen - tLen - 3; // Subtracting the prefix (0x00 || 0x01) and postfix (0x00) lengths
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
   * Converts an octet string (byte array) to a non-negative integer. This method follows the OS2IP
   * (Octet String to Integer Primitive) conversion as specified in cryptographic standards like
   * PKCS#1. 1. EMSA_PKCS1_v1_5 encoding: Apply the EMSA-PKCS1-v1_5 encoding operation to the
   * message M to produce an encoded message EM of length k octets where k is the length in bits of
   * the RSA modulus n:
   * <p>
   * EM = EMSA_PKCS1_v1_ENCODE (M, k).
   *
   * @param EM The encoded message as a byte array.
   * @return A BigInteger representing the non-negative integer obtained from the byte array.
   */
  public BigInteger OS2IP(byte[] EM) {
    return new BigInteger(1, EM);
  }

  /**
   * A custom implementation of the RSA signature primitive. Calculates the RSA signature of a given
   * message representative by computing the eth root/ dth power.
   * <p>
   * b. Apply the RSASP1 signature primitive to the RSA private key K and the
   * message representative m to produce an integer signature representative s:
   * <p>
   * s = RSASP1 (K, m).
   *
   * @param m The message representative, an integer representation of the message.
   * @return The signature representative, an integer representation of the signature.
   */
  public BigInteger RSASP1(BigInteger m) {
    BigInteger s = m.modPow(this.exponent, this.modulus);
    return s;
  }

}





