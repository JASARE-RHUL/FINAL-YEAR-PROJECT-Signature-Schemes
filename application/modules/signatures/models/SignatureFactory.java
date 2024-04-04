package uk.msci.project.rsa;

import uk.msci.project.rsa.exceptions.InvalidSignatureTypeException;
import uk.msci.project.rsa.SigScheme;
import uk.msci.project.rsa.SignatureType;
import uk.msci.project.rsa.Key;

/**
 * Factory class for creating instances of various signature schemes.
 * This class provides a static method to obtain an instance of a specific
 * signature scheme based on the type of signature and key provided. It supports
 * multiple signature types as defined in the SignatureType enumeration.
 */
public class SignatureFactory {

  /**
   * Retrieves an instance of the signature scheme corresponding to the
   * specified type.
   * This method acts as a centralised point for obtaining different types of
   * signature
   * schemes, ensuring that each scheme is correctly initialized with the
   * provided key
   * and additional parameters if required.
   *
   * @param signatureType    The type of signature scheme to be instantiated,
   *                        as defined in
   *                         the SignatureType enumeration.
   * @param key              The RSA key to be used for initialising the
   *                         signature scheme.
   *                         This key should be appropriate for the type of
   *                         signature scheme
   *                         being requested.
   * @param isProvablySecure A boolean flag indicating whether the scheme
   *                         should be
   *                         initialised in a provably secure mode, if
   *                         applicable. This
   *                         parameter might not affect all types of
   *                         signature schemes.
   * @return An instance of the requested signature scheme, properly
   * initialised with
   * the provided key and configured based on the isProvablySecure flag.
   * @throws InvalidSignatureTypeException if the provided signature type is
   * not recognised
   *                                       or supported. This ensures that
   *                                       only valid and
   *                                       implemented signature types can be
   *                                       instantiated.
   */
  public static SigScheme getSignatureScheme(SignatureType signatureType,
                                             Key key, boolean isProvablySecure)
    throws InvalidSignatureTypeException {
    switch (signatureType) {
      case RSASSA_PKCS1_v1_5:
        return new uk.msci.project.rsa.RSASSA_PKCS1_v1_5(key, isProvablySecure);
      case ANSI_X9_31_RDSA:
        return new uk.msci.project.rsa.ANSI_X9_31_RDSA(key, isProvablySecure);
      case ISO_IEC_9796_2_SCHEME_1:
        return new uk.msci.project.rsa.ISO_IEC_9796_2_SCHEME_1(key,
          isProvablySecure);
      default:
        throw new InvalidSignatureTypeException("Invalid signature type");
    }
  }

  /**
   * Determines if the specified signature type supports message recovery.
   *
   * @param signatureType The type of the signature to be evaluated.
   * @return A boolean value indicating whether message recovery is supported
   * by the given signature type.
   * Returns {@code true} for signature types with message recovery
   * capabilities and {@code false} otherwise.
   * @throws InvalidSignatureTypeException If the specified signature type is
   * not recognized or supported.
   *                                       This exception is thrown to
   *                                       indicate an unsupported or invalid
   *                                       type.
   */
  public static boolean getRecoveryStatus(SignatureType signatureType)
    throws InvalidSignatureTypeException {
    switch (signatureType) {
      case RSASSA_PKCS1_v1_5:
      case ANSI_X9_31_RDSA:
        return false;
      case ISO_IEC_9796_2_SCHEME_1:
        return true;
      default:
        throw new InvalidSignatureTypeException("Invalid signature type");
    }
  }
}
