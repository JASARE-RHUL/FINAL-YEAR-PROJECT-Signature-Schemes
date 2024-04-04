package uk.msci.project.rsa;

import java.math.BigInteger;

/**
 * Provides utility methods for converting BigInteger to fixed-length byte
 * arrays, commonly used in
 * cryptographic operations.
 */
public class ByteArrayConverter {

  /**
   * Converts a BigInteger to a byte array of a specified fixed length. This
   * method ensures that the
   * byte array has the exact number of bytes as defined by emLen.
   *
   * @param number The BigInteger to be converted into a byte array.
   * @param emLen  The bit length based on which the size of the byte array
   *               is determined.
   * @return A byte array of length emBits/8 containing the two's-complement
   * representation of the
   * BigInteger.
   * @throws IllegalArgumentException If the BigInteger's byte array is not
   * of the expected length
   *                                  or has an unexpected leading byte.
   */
  public static byte[] toFixedLengthByteArray(BigInteger number, int emLen)
    throws IllegalArgumentException {
    byte[] numberBytes = number.toByteArray();
    byte[] fixedLengthBytes = new byte[emLen];

    if (numberBytes.length == emLen) {
      // If the length is already correct, just return the array
      fixedLengthBytes = numberBytes;
    } else if (numberBytes.length < emLen) {
      // If the numberBytes array is too short, pad it with leading zeros
      System.arraycopy(numberBytes, 0, fixedLengthBytes,
        emLen - numberBytes.length,
        numberBytes.length);
    } else if (numberBytes.length == emLen + 1 && numberBytes[0] == 0) {
      // If numberBytes has an extra leading zero byte, remove it
      System.arraycopy(numberBytes, 1, fixedLengthBytes, 0, emLen);
    } else {
      // If none of the above conditions are met, the array length is invalid
      throw new IllegalArgumentException("The length of the byte array is " +
        "incorrect");
    }

    return fixedLengthBytes;
  }

}
