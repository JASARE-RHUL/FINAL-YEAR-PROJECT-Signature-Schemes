package uk.msci.project.rsa;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.DataFormatException;
import uk.msci.project.rsa.exceptions.InvalidDigestException;

/**
 * This abstract class provides a specialised framework for implementing a signature scheme using
 * the RSA algorithm. It implements the SigSchemeInterface and provides concrete and standardised
 * implementations of some of its methods, along with additional functionality specific to RSA-based
 * signature schemes.
 * <p>
 * Key components are encapsulated within the class, allowing for a modular and extensible design
 * suitable for various RSA-based signature schemes.
 */
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
  Key key;

  /**
   * The MessageDigest instance used for hashing.
   */
  MessageDigest md;

  /**
   * The identifier of the hash algorithm used.
   */
  byte[] hashID;

  Map<DigestType, byte[]> hashIDmap = new HashMap<DigestType, byte[]>();

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
   * Flag to indicate whether the signature scheme should use provably secure parameters. When set
   * to true, the scheme uses a mask generation function (MGF1) with the hash algorithm to generate
   * a large hash output
   */
  boolean isProvablySecureParams;

  /**
   * Size of the hash used in the encoding process, set to 32 bytes (SHA-256) by default.
   */
  int hashSize = 32;

  /**
   * Constructs a Signature scheme instance with the specified RSA key. This constructor initialises
   * the RSA key components (modulus and exponent), calculates the encoded message length, and sets
   * up the SHA-256 message digest as the default hashing algorithm.
   *
   * @param key The RSA key containing the exponent and modulus. This key is used for signature
   *            operations within the scheme.
   */
  public SigScheme(Key key) {
    initialise(key);
  }

  /**
   * Constructs a Signature scheme instance with the specified RSA key and a flag indicating whether
   * provably secure parameters are to be used. This constructor initialises the RSA key components,
   * calculates the encoded message length, sets up the SHA-256 message digest, and sets the flag
   * for using provably secure parameters.
   *
   * @param key                    The RSA key containing the exponent and modulus. This key is used
   *                               for signature operations within the scheme.
   * @param isProvablySecureParams A boolean flag indicating if provably secure parameters should be
   *                               used in the signature scheme.
   */
  public SigScheme(Key key, boolean isProvablySecureParams) {
    initialise(key);
    this.isProvablySecureParams = isProvablySecureParams;
    this.hashSize = isProvablySecureParams ? (emLen + 1) / 2 : md.getDigestLength();
  }

  /**
   * Initialises the signature scheme with the given RSA key. This method sets the RSA key
   * components (modulus and exponent), calculates the encoded message length (emLen), and attempts
   * to set up the SHA-256 message digest as the default hashing algorithm.
   *
   * @param key The RSA key to be used in the signature scheme.
   * @throws RuntimeException If the SHA-256 hashing algorithm is not available in the environment.
   */
  public void initialise(Key key) {
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
    } catch (NoSuchAlgorithmException e) {
      // NoSuchAlgorithmException is a checked exception, RuntimeException allows an exception to
      // be thrown if the algorithm isn't available.
      throw new RuntimeException("SHA-256 algorithm not available", e);
    }
  }


  /**
   * Encodes a message according to concrete signature scheme.
   *
   * @param M The message to be encoded.
   * @return The encoded message as a byte array.
   * @throws DataFormatException if the signature format is not valid.
   */
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
   * Converts a BigInteger to an octet string of length emLen where emLen is the ceiling of ((emBits
   * - 1)/8) and emBits is the bit length of the RSA modulus.
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
   * Calculates the RSA signature of a given message representative by raising it to the power of
   * the private exponent as outlined by the RSA algorithm.
   *
   * @param m The message representative, an integer representation of the message.
   * @return The signature representative, an integer representation of the signature.
   */
  public BigInteger RSASP1(BigInteger m) {
    BigInteger s = m.modPow(this.exponent, this.modulus);
    return s;
  }

  /**
   * Facilitates the verification of RSA signature by raising it to the power of the public exponent
   * as outlined by the RSA algorithm.
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

  /**
   * Sets the message digest for this instance according to the specified DigestType. This method
   * uses the DigestFactory to obtain an instance of MessageDigest corresponding to the given type.
   * It also updates the hashID to match the chosen digest type.
   *
   * @param digestType The type of the digest to be used for generating or verifying signatures.
   * @throws NoSuchAlgorithmException If the algorithm for the requested digest type is not
   *                                  available.
   * @throws InvalidDigestException   If the specified digest type is not supported or invalid.
   */
  public void setDigest(DigestType digestType)
      throws NoSuchAlgorithmException, InvalidDigestException {
    this.md = DigestFactory.getMessageDigest(digestType);
    this.hashID = hashIDmap.get(digestType);
  }

  /**
   * Computes the hash of the given message using the current message digest algorithm. This method
   * updates the message digest with the given message and then completes the hash computation.
   *
   * @param message The message to be hashed, represented as a byte array.
   * @return A byte array representing the hash of the message.
   */
  public byte[] computeHash(byte[] message) {
    this.md.update(message);
    return md.digest();
  }

  /**
   * Computes the hash of the given message with an optional security enhancement. If the flag for
   * provably secure parameters is set, this method applies a mask generation function (MGF1) to
   * generate a masked hash. Otherwise, it performs a standard hash computation.
   *
   * @param message The message to be hashed, represented as a byte array.
   * @return A byte array representing either the standard hash or the masked hash of the message.
   */
  public byte[] computeHashWithOptionalMasking(byte[] message) {
    return isProvablySecureParams ? new MGF1(this.md).generateMask(message, this.hashSize)
        : computeHash(message);
  }


}
