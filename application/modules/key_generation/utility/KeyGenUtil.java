package uk.msci.project.rsa;

/**
 * Utility class providing methods for operations related to key generation
 * processes.
 */
public class KeyGenUtil {
  /**
   * Converts a string of comma-separated numbers into an array of integers.
   * This method
   * is useful for parsing string representations of key size parameters into
   * a usable
   * format for RSA key generation. The method gracefully handles invalid
   * numbers by
   * substituting them with a large default value that typically triggers error
   * handling in the key generation process.
   *
   * @param s The string containing the comma-separated numbers.
   * @return An array of integers where each element is derived from the
   * comma-separated string. Invalid or excessively large numbers
   * are replaced with a default large value.
   */
  public static int[] convertStringToIntArray(String s) {

    String[] numberStrings = s.split("\\s*,\\s*");
    int[] intArray = new int[numberStrings.length];
    int k = numberStrings.length;
    for (int i = 0; i < k; i++) {
      // if number is too big to parse as Integer
      // pass, use a bit size larger than the maximum bit size
      // to cause the process to fail
      try {
        intArray[i] = Integer.parseInt(numberStrings[i]);
      } catch (NumberFormatException e) {
        intArray[i] = 8000;
      }
    }
    return intArray;

  }

}
