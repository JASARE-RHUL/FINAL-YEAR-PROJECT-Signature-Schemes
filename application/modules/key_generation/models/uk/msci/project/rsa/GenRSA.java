package uk.msci.project.rsa;

import static java.math.BigInteger.ONE;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * The GenRSA class is responsible for generating RSA key pairs. It allows for the creation of keys
 * with a modulus derived from multiple distinct prime numbers, offering flexibility in terms of the
 * number and size of these primes.
 */
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
   * The number of distinct prime numbers used to generate the RSA modulus.
   */
  private int k;

  /**
   * An array holding the bit lengths for each of the distinct prime numbers.
   */
  private int[] lambda;

  /**
   * Constructs a GenRSA object that can generate RSA keys with a modulus derived from k distinct
   * primes with specified bit lengths.
   *
   * @param k      The number of distinct primes to be generated.
   * @param lambda An array of integers representing the bit lengths of each prime number.
   * @throws IllegalArgumentException If the lambda array does not have k elements or if the sum of
   *                                  bit lengths does not meet the key size requirements.
   */
  public GenRSA(int k, int[] lambda) throws IllegalArgumentException {
    if (lambda.length != k) {
      throw new IllegalArgumentException("Lambda array must have k elements.");
    }

    for (int bitLength : lambda) {
      keySize += bitLength;
    }
    if (!(keySize >= MINKEYSIZE && keySize <= MAXKEYSIZE && k > 1)) {
      throw new IllegalArgumentException(
          "Key size cannot be smaller than " + MINKEYSIZE + "bits or larger than" + MAXKEYSIZE
              + "bits");
    }

    this.k = k;
    this.lambda = lambda;
  }

  /**
   * Generates an array of k distinct prime numbers based on the provided bit lengths.
   *
   * @return An array of BigInteger representing the distinct prime numbers.
   */
  public BigInteger[] generatePrimeComponents() {
    BigInteger[] components = new BigInteger[k];
    for (int i = 0; i < k; i++) {
      components[i] = new BigInteger(lambda[i], this.certainty, new SecureRandom());
    }
    return components;
  }

  /**
   * Computes the Euler's totient function (φ) for an RSA modulus that is the product of k distinct
   * prime numbers.
   *
   * @param components An array of BigInteger representing the distinct prime numbers.
   * @return The result of the Euler's totient function.
   */
  public BigInteger computePhi(BigInteger[] components) {
    BigInteger phi = BigInteger.ONE;
    for (BigInteger prime : components) {
      phi = phi.multiply(prime.subtract(ONE));
    }
    return phi;
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
   * Generates the RSA modulus by multiplying a given array of prime numbers.
   *
   * @param primes An array of BigInteger prime numbers.
   * @return The RSA modulus as a BigInteger, resulting from the product of the prime numbers.
   */
  public BigInteger genModulus(BigInteger[] primes) {
    BigInteger modulus = BigInteger.ONE;
    for (BigInteger prime : primes) {
      modulus = modulus.multiply(prime);
    }
    return modulus;
  }


  /**
   * Generates the RSA key pair.
   *
   * @return A {@code KeyPair} object containing the generated RSA public and private keys.
   */
  public KeyPair generateKeyPair() {
    BigInteger[] primes = this.generatePrimeComponents();
    BigInteger N = genModulus(primes);
    BigInteger phi = computePhi(primes);
    BigInteger e = computeE(phi);
    /*
     * Computes the private exponent d for private key component in the RSA Key pair.
     */
    BigInteger d = e.modInverse(phi);
    PublicKey publicKey = new PublicKey(N, e);
    PrivateKey privateKey = new PrivateKey(N, primes, phi, e, d);

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
