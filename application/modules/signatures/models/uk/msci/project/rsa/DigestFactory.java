package uk.msci.project.rsa;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import uk.msci.project.rsa.exceptions.InvalidDigestException;

/**
 * The  class provides a method to create MessageDigest instances based on a given DigestType.
 */
public class DigestFactory {

  /**
   * Creates and returns a MessageDigest instance corresponding to the specified DigestType.
   * Currently supports SHA-256 and SHA-512 hash functions.
   *
   * @param digestType The type of the digest to be created, defined by the DigestType enum.
   * @return A MessageDigest instance corresponding to the specified type.
   * @throws InvalidDigestException   If the specified digest type is not supported or invalid.
   * @throws NoSuchAlgorithmException If the algorithm for the requested digest type is not
   *                                  available.
   */
  public static MessageDigest getMessageDigest(DigestType digestType)
      throws InvalidDigestException, NoSuchAlgorithmException {
    switch (digestType) {
      case SHA_256:
        return MessageDigest.getInstance("SHA-256");
      case SHA_512:
        return MessageDigest.getInstance("SHA-512");
      default:
        throw new InvalidDigestException("Invalid hash function type");
    }
  }
}
