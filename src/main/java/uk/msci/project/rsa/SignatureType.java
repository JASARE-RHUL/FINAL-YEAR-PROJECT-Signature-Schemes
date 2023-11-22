package uk.msci.project.rsa;

/**
 * This Enum represents full suite of deterministic digital signature schemes.
 */
public enum SignatureType {

  /**
   * Signature scheme RSASSA PKCS1 v1.5.
   */
  RSASSA_PKCS1_v1_5("RSASSA_PKCS1_v1_5"),

  /**
   * Signature scheme ANSI X9.31 for RSA Digital Signatures.
   */
  ANSI_X9_31_RDSA("ANSI_X9_31_RDSA"),

  /**
   * Signature scheme ISO/IEC 9796-2 Scheme 1.
   */
  ISO_IEC_9796_2_SCHEME_1("ISO_IEC_9796_2_SCHEME_1");

  private final String schemeName;

  /**
   * Constructs a new signature type with the specified scheme name.
   *
   * @param schemeName The name of the signature scheme.
   */
  SignatureType(String schemeName) {
    this.schemeName = schemeName;
  }

  /**
   * Returns the scheme name of the signature type.
   *
   * @return The name of the signature scheme.
   */
  public String getSchemeName() {
    return this.schemeName;
  }

  /**
   * Returns the string representation of the signature type. This method overrides the {@code
   * toString} method in the enum superclass.
   *
   * @return The name of the signature scheme as a string.
   */
  @Override
  public String toString() {
    return schemeName;
  }
}
