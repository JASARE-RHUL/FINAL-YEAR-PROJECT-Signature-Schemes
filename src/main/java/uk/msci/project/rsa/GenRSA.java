package uk.msci.project.rsa;

import java.math.BigInteger;
import java.security.SecureRandom;

public class GenRSA {

  /**
   * The maximum allowed key size in bits.
   */
  private static final int MAXKEYSIZE = 7680;

  /**
   * The minimum allowed key size in bits.
   */
  private static final int MINKEYSIZE = 1024;

  /**
   * The size of the key to be generated.
   */
  private int keySize;

  /**
   * Constructs a {@code KeyGenerator2} object with a specified key size.
   *
   * @param size The desired bit length of the RSA keys.
   * @throws IllegalArgumentException if the specified key size is invalid.
   */
  public GenRSA(int size) throws IllegalArgumentException {
    if (size >= MINKEYSIZE && size <= MAXKEYSIZE) {
      this.keySize = size;
    } else {
      throw new IllegalArgumentException(
          "Key size cannot be smaller than " + MINKEYSIZE + "bits or larger than" + MAXKEYSIZE
              + "bits");
    }
  }

  /**
   * Generates two probable prime numbers of bit length roughly equal to half of the specified key
   * size.
   *
   * @return An array of two {@code BigInteger} instances representing the prime numbers.
   */
  public BigInteger[] generatePrimeComponents() {
    int adjustedBitLength = (int) Math.ceil(((double) keySize) / 2);
    BigInteger p = new BigInteger(adjustedBitLength, 75, new SecureRandom());
    BigInteger q = new BigInteger(adjustedBitLength, 75, new SecureRandom());
    if (p.equals(q)) {
      return this.generatePrimeComponents();
    }
    return new BigInteger[]{p, q};
  }

  /**
   * Returns the size of the key to be generated.
   *
   * @return The bit length of the RSA keys.
   */
  public int getKeySize() {
    return this.keySize;
  }

}
