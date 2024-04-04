package uk.msci.project.rsa;

/**
 * Enum representing the various cryptographic hash functions supported in
 * the digital signature
 * schemes. This enumeration facilitates the selection and use of different
 * hash functions,
 * including SHA-256, SHA-512, and SHAKE variants, in the context of
 * cryptographic operations.
 */
public enum DigestType {

  /**
   * SHA-256 hash function. Provides a standard cryptographic hash function
   * with a fixed output size
   * of 256 bits.
   */
  SHA_256("SHA-256"),

  /**
   * SHA-512 hash function. Offers a cryptographic hash function with a fixed
   * output size of 512
   * bits, providing a higher level of security than SHA-256.
   */
  SHA_512("SHA-512"),

  /**
   * SHAKE-128 hash function. A member of the SHA-3 family of hash functions,
   * capable of producing
   * variable-length output. SHAKE-128 is designed for flexibility and security.
   */
  SHAKE_128("SHAKE-128"),

  /**
   * SHAKE-256 hash function. Similar to SHAKE-128, this hash function is
   * part of the SHA-3 family
   * and can produce a variable-length output but with a higher security
   * level than SHAKE-128.
   */
  SHAKE_256("SHAKE-256"),

  /**
   * MGF1 with SHA-256 hash function. Represents a mask generation function
   * using SHA-256. It's
   * often used in cryptographic protocols requiring data masking with a hash
   * function like
   * SHA-256.
   */
  MGF_1_SHA_256("SHA-256 with MGF1"),

  /**
   * MGF1 with SHA-512 hash function. Similar to MGF1 with SHA-256 but
   * utilizes SHA-512 for
   * cryptographic operations requiring a higher security level.
   */
  MGF_1_SHA_512("SHA-512 with MGF1");

  /**
   * The name of the hash digest. This field stores a string representation
   * of the hash function,
   * which can be used for identification and selection purposes in
   * cryptographic operations.
   */
  private final String digestName;

  /**
   * Constructs a new DigestType enumeration with the specified digest name.
   *
   * @param digestName The name of the hash digest. This name is used for
   *                   identifying the specific
   *                   hash function represented by the enumeration value.
   */
  DigestType(String digestName) {
    this.digestName = digestName;
  }

  /**
   * Returns the name of the digest.
   *
   * @return The name of the digest as specified in the constructor.
   */
  public String getDigestName() {
    return this.digestName;
  }

  /**
   * Provides the string representation of the digest type.
   *
   * @return A string that represents the name of the digest type.
   */
  @Override
  public String toString() {
    return digestName;
  }

  /**
   * Converts a custom string representation of a hash function into its
   * corresponding {@link
   * DigestType} enum value. This method is particularly useful for parsing
   * string inputs (such as
   * from a configuration file or user input) into the defined hash function
   * types.
   *
   * @param s The string representation of the digest type. Expected values
   *          include "SHA-256",
   *          "SHA-512", "SHAKE-128", "SHAKE-256", "SHA-256 with MGF1", and
   *          "SHA-512 with MGF1".
   * @return The corresponding {@link DigestType} enum value if the input
   * string matches any known
   * digest type, or {@code null} if there is no match.
   */
  public static DigestType getDigestTypeFromCustomString(String s) {
    if (s == null) {
      return null;
    }

    return switch (s) {
      case "SHA-256" -> SHA_256;
      case "SHA-512" -> SHA_512;
      case "SHAKE-128" -> SHAKE_128;
      case "SHAKE-256" -> SHAKE_256;
      case "SHA-256 with MGF1" -> MGF_1_SHA_256;
      case "SHA-512 with MGF1" -> MGF_1_SHA_512;
      default -> null;
    };
  }
}
