package uk.msci.project.rsa;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * The DigestFactory class provides a method to create MessageDigest instances based on a given
 * DigestType.
 */
public class DigestFactory {

  /**
   * Creates and returns a MessageDigest instance corresponding to the specified DigestType.
   *
   * @param digestType The type of the digest to be created, defined by the DigestType enum.
   * @return A MessageDigest instance corresponding to the specified type.
   * @throws NoSuchAlgorithmException If the algorithm for the requested digest type is not
   *                                  available.
   * @throws NoSuchProviderException  If the BouncyCastle provider is not available when trying to
   *                                  create a SHAKE message digest.
   */
  public static MessageDigest getMessageDigest(DigestType digestType)
      throws NoSuchAlgorithmException, NoSuchProviderException {
    switch (digestType) {
      case SHA_256 -> {

        return MessageDigest.getInstance("SHA-256");
      }
      case MGF_1_SHA_256 -> {

        return MessageDigest.getInstance("SHA-256");
      }
      case SHA_512 -> {
        return MessageDigest.getInstance("SHA-512");
      }
      case MGF_1_SHA_512 -> {
        return MessageDigest.getInstance("SHA-512");
      }
      case SHAKE_128 -> {
        Security.addProvider(new BouncyCastleProvider());
        return MessageDigest.getInstance("SHAKE128", BouncyCastleProvider.PROVIDER_NAME);
      }
      case SHAKE_256 -> {
        Security.addProvider(new BouncyCastleProvider());
        return MessageDigest.getInstance("SHAKE256", BouncyCastleProvider.PROVIDER_NAME);
      }
      default -> throw new NoSuchAlgorithmException("Unsupported digest type: " + digestType);
    }
  }

}
