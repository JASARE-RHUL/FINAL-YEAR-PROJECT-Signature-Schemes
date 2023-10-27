package uk.msci.project.rsa;

import static java.math.BigInteger.ONE;

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
   * The certainty level for prime number generation. The higher the value, the more certain it is
   * that the generated numbers are prime.
   */
  private int certainty = 75;

  /**
   * Constructs a GenRSA object with a specified key size.
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
    BigInteger p = new BigInteger(adjustedBitLength, this.certainty, new SecureRandom());
    BigInteger q = new BigInteger(adjustedBitLength, this.certainty, new SecureRandom());
    if (p.equals(q)) {
      return this.generatePrimeComponents();
    }
    return new BigInteger[]{p, q};
  }

  /**
   * Computes the Euler's totient function of {@code p} and {@code q}.
   *
   * @param p The first prime factor of the modulus N.
   * @param q The second prime factor of modulus N.
   * @return The result of Euler's totient function.
   */
  public BigInteger computePhi(BigInteger p, BigInteger q) {
    return p.subtract(ONE).multiply(q.subtract(ONE));
  }

  /**
   * Computes the public exponent {@code e} for public key component in the RSA Key pair.
   *
   * @param phi The result of Euler's totient function.
   * @return The public exponent {@code e}.
   */
  public BigInteger computeE(BigInteger phi) {
    BigInteger e = new BigInteger(phi.bitLength(), new SecureRandom());
    while (e.compareTo(ONE) <= 0 || !phi.gcd(e).equals(ONE) || e.compareTo(phi) >= 0) {
      e = new BigInteger(phi.bitLength(), new SecureRandom());
    }
    return e;
  }

  /**
   * Generates the RSA key pair.
   *
   * @return A {@code KeyPair} object containing the generated RSA public and private keys.
   */
  public KeyPair generateKeyPair() {
    BigInteger[] pq = this.generatePrimeComponents();
    BigInteger p = pq[0];
    BigInteger q = pq[1];
    BigInteger N = p.multiply(q);
    BigInteger phi = computePhi(p, q);
    BigInteger e = computeE(phi);
    /*
     * Computes the private exponent d for private key component in the RSA Key pair.
     */
    BigInteger d = e.modInverse(phi);
    PublicKey publicKey = new PublicKey(N, e);
    PrivateKey privateKey = new PrivateKey(N, d);

    return new KeyPair(publicKey, privateKey);
  }

  /**
   * Returns the size of the key to be generated.
   *
   * @return The bit length of the RSA keys.
   */
  public int getKeySize() {
    return this.keySize;
  }

  /**
   * Returns the certainty level used for prime number generation. The higher the certainty, the
   * more certain it is that the generated numbers are prime.
   *
   * @return The certainty level for prime number generation.
   */
  public int getCertainty() {
    return this.certainty;
  }

}
