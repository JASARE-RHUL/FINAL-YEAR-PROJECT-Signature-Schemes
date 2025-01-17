package uk.msci.project.rsa;

import java.math.BigInteger;
import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.zip.DataFormatException;
import uk.msci.project.rsa.exceptions.InvalidDigestException;
import uk.msci.project.rsa.MGF1;
import uk.msci.project.rsa.ByteArrayConverter;
import uk.msci.project.rsa.DigestFactory;
import uk.msci.project.rsa.Key;
import uk.msci.project.rsa.SigSchemeInterface;
import uk.msci.project.rsa.DigestType;
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
   * The current hash type being used.
   */
  DigestType currentHashType;

  /**
   * Indicates whether this signature scheme is message recovery scheme.
   */
  boolean isRecoveryScheme;


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
    byte[] EM;
    try {
      EM = encodeMessage(M);
    } catch (Exception e) {
      throw new DataFormatException("Custom hash size is is too large");
    }
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
    byte[] EMprime;
    try {
      EM = I2OSP(m);
      EMprime = encodeMessage(M);
    } catch (DataFormatException | IllegalArgumentException e) {
      return false;
    }

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
    return nonRecoverableM == null ? new byte[]{} : nonRecoverableM;
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
   * Sets the message digest algorithm to be used for hashing in the signature scheme and
   * automatically configures the hash size based on the type of hash and the "provably secure"
   * flag
   *
   * @param digestType The type of message digest algorithm to be set.
   * @throws NoSuchAlgorithmException If the specified algorithm is not available in the
   *                                  environment.
   * @throws InvalidDigestException   If the specified digest type is invalid or unsupported.
   * @throws NoSuchProviderException  If the specified provider for the algorithm is not available.
   * @throws IllegalArgumentException If a custom hash size is not a positive integer.
   */
  public void setDigest(DigestType digestType)
      throws NoSuchAlgorithmException, InvalidDigestException, NoSuchProviderException {
    this.currentHashType = digestType;
    setDigest(digestType, 0); // Default hash size for the given digest type
  }

  /**
   * Sets the message digest algorithm to be used for hashing in the signature scheme to the
   * specified digest type. It allows setting a custom hash size for variable-length hash types
   * (like Hash functions with MGF or SHAKE types) when the "provably secure" flag is not set. For
   * fixed-size hash types, the method ignores the custom hash size and uses the default size.
   *
   * @param digestType     The type of message digest algorithm to be set.
   * @param customHashSize The custom hash size, used only for variable-length hash types.
   * @throws NoSuchAlgorithmException If the specified algorithm is not available in the
   *                                  environment.
   * @throws InvalidDigestException   If the specified digest type is invalid or unsupported.
   * @throws NoSuchProviderException  If the specified provider for the algorithm is not available.
   * @throws IllegalArgumentException If a custom hash size is not a positive integer.
   */
  public void setDigest(DigestType digestType, int customHashSize)
      throws NoSuchAlgorithmException, InvalidDigestException, NoSuchProviderException {
    md.reset();
    this.currentHashType = digestType;
    this.md = DigestFactory.getMessageDigest(digestType);
    this.hashID = getHashID(currentHashType);

    if (digestType == DigestType.SHA_256 || digestType == DigestType.SHA_512) {
      this.hashSize = md.getDigestLength(); // Fixed size
    } else if (isProvablySecureParams) {
      this.hashSize = (emLen + 1) / 2; // Provably secure size
    } else {
      if (customHashSize <= 0) {
        throw new IllegalArgumentException("Custom hash size must be a positive integer");
      }
      this.hashSize = customHashSize; // Custom size for variable-length hash types
    }
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
   * Computes a SHAKE hash of the given message using the current message digest algorithm. SHAKE
   * (Secure Hash Algorithm Keccak) is a cryptographic hash function that can produce a
   * variable-length output, allowing flexibility in hash sizes, for example, SHAKE-128.
   *
   * <p>The resulting hash is generated from the provided message.</p>
   *
   * @param message The message to be hashed, represented as a byte array.
   * @return A byte array representing the SHAKE hash of the message.
   */
  public byte[] computeShakeHash(byte[] message) {
    this.md.update(message);
    byte[] output = new byte[this.hashSize];
    // Complete the hash computation with the specified output length
    try {
      this.md.digest(output, 0, this.hashSize);
    } catch (DigestException e) {
      e.printStackTrace();
    }
    return output;
  }

  /**
   * Computes a hash of the given message. The resulting hash can have a variable length if the
   * currently set hash function supports an extendable output, such as SHAKE-128 or MGF1 with a
   * fixed underlying hash function like SHA-256.
   *
   * <p>If the hash function is not fixed-size and is set to MGF1 with SHA-256 or SHA-512, masking
   * is applied to generate a hash of the specified size.</p>
   *
   * @param message The message to be hashed, represented as a byte array.
   * @return A byte array representing the hash of the message.
   */
  public byte[] computeHashWithOptionalMasking(byte[] message) {
    if (!(currentHashType == DigestType.SHA_256 || currentHashType == DigestType.SHA_512)) {
      if (currentHashType == DigestType.MGF_1_SHA_256
          || currentHashType == DigestType.MGF_1_SHA_512) {
        return new MGF1(this.md).generateMask(message, this.hashSize);
      } else {
        return computeShakeHash(message);
      }
    } else {
      return computeHash(message);
    }
  }


  /**
   * Returns the current type of hash function set in the signature scheme.
   *
   * @return The current type of hash function being used with in the signature scheme.
   */
  public DigestType getHashType() {
    return currentHashType;
  }

  /**
   * Retrieves the hash ID associated with a given digest type.
   *
   * @param digestType The type of digest algorithm for which the hash ID is required.
   * @return A byte array representing the hash ID associated with the specified digest type.
   * @throws IllegalArgumentException If the provided digest type is not supported.
   */
  public abstract byte[] getHashID(DigestType digestType);



  /**
   * Retrieves the status indicating whether the signature scheme supports message recovery.
   *
   * @return true if the signature scheme is a message recovery scheme, false otherwise.
   */
  boolean getRecoveryStatus() {
    return isRecoveryScheme;
  }


}
