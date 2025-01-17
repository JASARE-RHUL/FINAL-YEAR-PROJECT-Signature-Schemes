package uk.msci.project.rsa;

import java.math.BigInteger;
import java.security.SignatureException;
import java.util.zip.DataFormatException;


/**
 * This interface defines the essential functionalities of a signature scheme.
 * <p>
 * It is intended to be implemented by classes that provide concrete
 * implementations of signature
 * schemes. The methods defined are fundamental to any digital signature
 * scheme and provide a
 * standardised contract to sign and verify data.
 */
public interface SigSchemeInterface {

  /**
   * Signs the provided data.
   *
   * @param M Data to be signed.
   * @return The digital signature.
   * @throws DataFormatException if the signature format is not valid.
   */
  byte[] sign(byte[] M) throws DataFormatException;

  /**
   * Verifies a given signature.
   *
   * @param data      Original data that was signed.
   * @param signature The digital signature to be verified.
   * @return true if the signature is valid, false otherwise.
   * @throws DataFormatException if there's an error during verification.
   */
  boolean verify(byte[] data, byte[] signature) throws DataFormatException;

  /**
   * Converts an octet string (byte array) to a non-negative integer.
   *
   * @param EM The encoded message as a byte array.
   * @return A BigInteger representing the non-negative integer obtained from
   * the byte array.
   */
  BigInteger OS2IP(byte[] EM);

  /**
   * Converts a BigInteger to an octet string of length emLen where emLen is
   * the ceiling of
   * ((modBits - 1)/8) and modBits is the bit length of the RSA modulus.
   *
   * @param m The BigInteger to be converted into an octet string.
   * @return A byte array representing the BigInteger in its octet string
   * form, of length emLen.
   * @throws IllegalArgumentException If the BigInteger's byte array
   * representation is not of the
   *                                  expected length or has an unexpected
   *                                  leading byte.
   */
  byte[] I2OSP(BigInteger m) throws IllegalArgumentException;

  /**
   * Calculates the RSA signature of a given message representative by
   * raising it to the power of
   * the private exponent as outlined by the RSA algorithm.
   *
   * @param m The message representative, an integer representation of the
   *          message.
   * @return The signature representative, an integer representation of the
   * signature.
   */
  BigInteger RSASP1(BigInteger m);

  /**
   * Facilitates the verification of RSA signature by raising it to the power
   * of the public exponent
   * as outlined by the RSA algorithm.
   *
   * @param s The signature representative, an integer representation of the
   *          signature.
   * @return The message representative, an integer representation of the
   * message.
   */
  BigInteger RSAVP1(BigInteger s);

}
