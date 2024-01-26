package uk.msci.project.rsa;

/**
 * This Enum represents the cryptographic hash functions supported by customised implementations of
 * digital signature schemes.
 */
public enum DigestType {

  /**
   * Cryptographic Hash Function: SHA-256.
   */
  SHA_256("SHA_256"),

  /**
   * Cryptographic Hash Function: SHA-512.
   */
  SHA_512("SHA_512");

  private final String digestName;

  /**
   * Constructs a new digest with the specified digest name.
   *
   * @param digestName The name of the signature scheme.
   */
  DigestType(String digestName) {
    this.digestName = digestName;
  }

  /**
   * Returns the digest name of the hash digest..
   *
   * @return The name of the digest.
   */
  public String getDigestName() {
    return this.digestName;
  }

  /**
   * Returns the string representation of the digest. This method overrides the {@code toString}
   * method in the enum superclass.
   *
   * @return The name of the digest as a string.
   */
  @Override
  public String toString() {
    return digestName;
  }
}
