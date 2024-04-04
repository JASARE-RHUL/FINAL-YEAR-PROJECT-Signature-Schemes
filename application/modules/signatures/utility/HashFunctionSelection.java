package uk.msci.project.rsa;

import uk.msci.project.rsa.DigestType;

/**
 * Represents a selection of a hash function along with its properties. This
 * class holds information
 * about the type of digest, its security level, and any custom size parameters.
 * <p>
 * This class allows for configuration of hash functions within the digital
 * signature process,
 * including selecting a specific hash function type (e.g., SHA-256),
 * determining whether the hash
 * function is provably secure/setting custom hash output sizes through
 * considering its size as a
 * fraction of a specified  modulus length.
 */
public class HashFunctionSelection {

  /**
   * The type of the digest used in the hash function.
   */
  private final DigestType digestType;

  /**
   * Indicates whether the hash function is provably secure.
   */
  private final boolean isProvablySecure;

  /**
   * Custom size parameters for the hash function, if applicable.
   */
  private final int[] customSize;

  /**
   * Constructs a new HashFunctionSelection with the specified properties.
   *
   * @param digestType       The type of the digest used in the hash function.
   * @param isProvablySecure Indicates whether the hash function is provably
   *                         secure.
   * @param customSize       Optional custom size parameters for the hash
   *                         function. used for
   *                         fine-tuning the hash output size based on the
   *                         modulus size.
   */

  public HashFunctionSelection(DigestType digestType,
                               boolean isProvablySecure, int[] customSize) {
    this.digestType = digestType;
    this.isProvablySecure = isProvablySecure;
    this.customSize = customSize;
  }

  /**
   * Returns the type of the digest used in the hash function.
   *
   * @return The digest type.
   */
  public DigestType getDigestType() {
    return digestType;
  }

  /**
   * Returns whether the hash function is provably secure.
   *
   * @return true if the hash function is provably secure, false otherwise.
   */
  public boolean isProvablySecure() {
    return isProvablySecure;
  }

  /**
   * Retrieves the custom size parameters of the hash function, if set.
   *
   * @return An array representing the custom size of the hash function, or
   * {@code null} if no
   * custom size is specified.
   */
  public int[] getCustomSize() {
    return customSize;
  }

  /**
   * Validates a given string representing a fractional value. The method
   * checks if the string
   * correctly represents a fraction in the format 'numerator/denominator'
   * where the numerator is
   * less than the denominator. The fraction is used to calculate custom hash
   * output sizes as a
   * proportion of a specified modulus length.
   *
   * @param customSize The string representation of the fraction to be
   *                   validated. The expected
   *                   format is 'numerator/denominator'.
   * @return An array of two integers {numerator, denominator} if the
   * fraction is valid, or {@code
   * null} if the input is invalid or if the numerator is not less than the
   * denominator.
   */
  public static int[] validateFraction(String customSize) {
    if (customSize != null && customSize.matches("^\\s*[1-9]\\d*\\/" +
      "([1-9]\\d*)\\s*$")) {
      String[] parts = customSize.trim().split("/");
      int numerator = Integer.parseInt(parts[0]);
      int denominator = Integer.parseInt(parts[1]);
      if (numerator < denominator) {
        return new int[]{numerator, denominator};
      }
    }
    return null;
  }
}
