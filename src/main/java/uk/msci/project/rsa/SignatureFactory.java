package uk.msci.project.rsa;

/**
 * This class is factory for returning the Signature scheme instance corresponding to a user
 * specified signature Type.
 */
public class SignatureFactory {
  /**
   * Gets the matching SignatureScheme instance required for a specific type of signature. This
   * method selects the appropriate signature scheme implementation based on the provided signature
   * type.
   *
   * @param signatureType The type of signature scheme required, passed in as an Enum.
   * @param key           The RSA key to be used to initialise the signature scheme.
   * @return The signature scheme corresponding to the provided type of SignatureType Enum,
   * initialized with the given key.
   * @throws InvalidSignatureTypeException if the parameter passed SignatureType is not valid or
   *                                       supported.
   */
  public static SigScheme getSignatureScheme(SignatureType signatureType, Key key)
      throws InvalidSignatureTypeException {
    switch (signatureType) {
      case RSASSA_PKCS1_v1_5:
        return new RSASSA_PKCS1_v1_5(key);
      case ANSI_X9_31_RDSA:
        return new ANSI_X9_31_RDSA(key);
      case ISO_IEC_9796_2_SCHEME_1:
        return new ISO_IEC_9796_2_SCHEME_1(key);
      default:
        throw new InvalidSignatureTypeException("Invalid signature type");
    }
  }
}
