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
    this.emLen = (this.emBits + 7) / 8; // Convert bits to bytes and round up if necessary..
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
  private BigInteger OS2IP(byte[] EM) {
    return new BigInteger(1, EM);
  }

  /*
   * c. Convert the message representative m to an encoded message EM
   *    of length emLen = \ceil ((modBits - 1)/8) octets, where modBits
   *    is the length in bits of the RSA modulus n (see Section 4.1):
   *
   *        EM = I2OSP (m, emLen).
   */

  /**
   * Converts a BigInteger to an octet string of length emLen. This method implements the I2OSP
   * (Integer-to-Octet-String Primitive) as specified in PKCS#1. It ensures that the resulting byte
   * array has a length of emLen bytes, where emLen is the ceiling of ((modBits - 1)/8) and modBits
   * is the bit length of the RSA modulus.
   * <p>
   * Convert the message representative m to an encoded message EM = I2OSP (m, emLen).
   *
   * @param m The BigInteger to be converted into an octet string.
   * @return A byte array representing the BigInteger in its octet string form, of length emLen.
   * @throws IllegalArgumentException If the BigInteger's byte array representation is not of the
   *                                  expected length or has an unexpected leading byte.
   */
  private byte[] I2OSP(BigInteger m) throws IllegalArgumentException {
    return ByteArrayConverter.toFixedLengthByteArray(m, this.emLen);
  }

  /**
   * A custom implementation of the RSA signature primitive. Calculates the RSA signature of a given
   * message representative by computing the eth root/ dth power.
   * <p>
   * b. Apply the RSASP1 signature primitive to the RSA private key K and the message representative
   * m to produce an integer signature representative s:
   * <p>
   * s = RSASP1 (K, m).
   *
   * @param m The message representative, an integer representation of the message.
   * @return The signature representative, an integer representation of the signature.
   */
  private BigInteger RSASP1(BigInteger m) {
    BigInteger s = m.modPow(this.exponent, this.modulus);
    return s;
  }

  /**
   * A custom implementation of the RSA verification primitive. Facilitates the verification of RSA
   * signature by enabling the computation of its eth power of a provided signature representative
   *
   * @param s The signature representative, an integer representation of the signature.
   * @return The message representative, an integer representation of the message.
   */
  private BigInteger RSAVP1(BigInteger s) {
    return this.RSASP1(s);
  }

}





