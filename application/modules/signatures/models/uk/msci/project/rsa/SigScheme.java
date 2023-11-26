package uk.msci.project.rsa;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.zip.DataFormatException;


public abstract class SigScheme implements SigSchemeInterface {

  /**
   * The exponent part of the RSA key.
   */
  BigInteger exponent;

  /**
   * The modulus part of the RSA key.
   */
  BigInteger modulus;

  /**
   * The bit length of the modulus minus one.
   */
  int emBits;

  /**
   * The maximum message length in bytes.
   */
  int emLen;

  /**
   * The RSA key containing the exponent and modulus.
   */
  final Key key;

  /**
   * The MessageDigest instance used for hashing.
   */
  MessageDigest md;

  /**
   * The identifier of the hash algorithm used.
   */
  byte[] hashID;

  /**
   * Non-recoverable portion of message as applicable to the signing process of a message recovery
   * scheme
   */
  byte[] nonRecoverableM;

  /**
   * Recoverable portion of message as applicable to the verification process of a message recovery
   * scheme
   */
  byte[] recoverableM;

  /**
   * Constructs a Signature scheme instance with the specified RSA key. Initialises the modulus and
   * exponent from the key, calculates the encoded message length, and sets up the SHA-256 message
   * digest along with a predefined hash ID.
   *
   * @param key The RSA key containing the exponent and modulus.
   */
  public SigScheme(Key key) {
    this.key = key;
    this.exponent = this.key.getExponent();
    this.modulus = this.key.getModulus();
    // emBits is the bit length of the modulus n, minus one.
    this.emBits = modulus.bitLength() - 1;
    // emLen is the maximum message length in bytes.
    this.emLen = (this.emBits + 7) / 8; // Convert bits to bytes and round up if necessary
    emLen--;
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

  // Abstract method to be implemented by derived classes for encoding
  protected abstract byte[] encodeMessage(byte[] M) throws DataFormatException;


  /**
   * Signs the provided message using RSA private key operations. The method encodes the message,
   * generates a signature, and returns it as a byte array.
   *
   * @param M The message to be signed.
   * @return The RSA signature of the message.
   * @throws DataFormatException If the message encoding fails.
   */
  @Override
  public byte[] sign(byte[] M) throws DataFormatException {
    byte[] EM = encodeMessage(M);
    BigInteger m = OS2IP(EM);

    BigInteger s = RSASP1(m);

    byte[] S = ByteArrayConverter.toFixedLengthByteArray(s, emLen + 1);

    // Output the signature S.
    return S;
  }

  /**
   * Verifies an RSA signature against a given message. Returns true if the signature is valid.
   *
   * @param M The original message.
   * @param S The RSA signature to be verified.
   * @return true if the signature is valid, false otherwise.
   * @throws DataFormatException If verification fails due to incorrect format.
   */
  @Override
  public boolean verify(byte[] M, byte[] S) throws DataFormatException {
    return verifyMessage(M, S);
  }

  /**
   * Verifies an RSA signature against a given message. Returns true if the signature is valid.
   *
   * @param M The original message.
   * @param S The RSA signature to be verified.
   * @return true if the signature is valid, false otherwise.
   * @throws DataFormatException If verification fails due to incorrect format.
   */
  public boolean verifyMessage(byte[] M, byte[] S)
      throws DataFormatException {
    BigInteger s = OS2IP(S);
    BigInteger m = RSAVP1(s);
    byte[] EM;
    try {
      EM = I2OSP(m);
    } catch (IllegalArgumentException e) {
      return false;
    }

    byte[] EMprime = encodeMessage(M);

    return Arrays.equals(EM, EMprime);
  }


  /**
   * Converts an octet string (byte array) to a non-negative integer.
   *
   * @param EM The encoded message as a byte array.
   * @return A BigInteger representing the non-negative integer obtained from the byte array.
   */
  public BigInteger OS2IP(byte[] EM) {
    return new BigInteger(1, EM);
  }


  /**
   * Converts a BigInteger to an octet string of length emLen where emLen is the ceiling of
   * ((modBits - 1)/8) and modBits is the bit length of the RSA modulus.
   *
   * @param m The BigInteger to be converted into an octet string.
   * @return A byte array representing the BigInteger in its octet string form, of length emLen.
   * @throws IllegalArgumentException If the BigInteger's byte array representation is not of the
   *                                  expected length or has an unexpected leading byte.
   */
  public byte[] I2OSP(BigInteger m) throws IllegalArgumentException {
    return ByteArrayConverter.toFixedLengthByteArray(m, this.emLen);
  }

  /**
   * Calculates the RSA signature of a given message representative by computing the eth root/ dth
   * power.
   *
   * @param m The message representative, an integer representation of the message.
   * @return The signature representative, an integer representation of the signature.
   */
  public BigInteger RSASP1(BigInteger m) {
    BigInteger s = m.modPow(this.exponent, this.modulus);
    return s;
  }

  /**
   * Facilitates the verification of RSA signature by enabling the computation of its eth power of a
   * provided signature representative
   *
   * @param s The signature representative, an integer representation of the signature.
   * @return The message representative, an integer representation of the message.
   */
  public BigInteger RSAVP1(BigInteger s) {
    return this.RSASP1(s);
  }

  /**
   * Gets the non-recoverable portion of message as generated by adjusted sign method for signature
   * schemes with message recovery
   *
   * @return signing process initialised non-recoverable portion of message
   */
  public byte[] getNonRecoverableM() {
    return nonRecoverableM;
  }

  /**
   * Gets recoverable portion of message as generated by adjusted verify method for signature
   * schemes with message recovery
   *
   * @return verification process initialised non-recoverable portion of message
   */
  public byte[] getRecoverableM() {
    return recoverableM;
  }


}
