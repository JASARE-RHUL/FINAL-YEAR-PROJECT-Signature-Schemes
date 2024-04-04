package uk.msci.project.rsa;

import static java.math.BigInteger.ONE;

import java.math.BigInteger;
import java.security.SecureRandom;

import uk.msci.project.rsa.KeyPair;
import uk.msci.project.rsa.PublicKey;
import uk.msci.project.rsa.PrivateKey;

/**
 * The GenRSA class is responsible for generating RSA key pairs. It allows
 * for the creation of keys
 * with a modulus derived from multiple distinct prime numbers, offering
 * flexibility in terms of the
 * number and size of these primes. This class also provides the capability
 * to use a smaller
 * exponent 'e', which can be beneficial in certain cryptographic
 * applications for efficiency or the
 * applicability of certain proofs.
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
   * The total key size in bits, derived from the sum of bit lengths of the
   * distinct prime numbers.
   */
  private int keySize;

  /**
   * The certainty level for prime number generation. The higher the value,
   * the more certain it is
   * that the generated numbers are prime.
   */
  private int certainty = 75;

  /**
   * The number of distinct prime numbers used in generating the RSA modulus.
   */
  private int k;

  /**
   * An array holding the bit lengths for each of the distinct prime numbers.
   * The sum of these bit
   * lengths contributes to the total key size.
   */
  private int[] lambda;

  /**
   * The bit length of the exponent 'e' used in RSA key generation. It can be
   * a 1/4 of the key size
   * depending on whether a small 'e' is desired.
   */
  private int eBitLength;


  /**
   * Constructs a GenRSA object capable of generating RSA keys. The modulus
   * is derived from 'k'
   * distinct prime numbers, each with a specified bit length given in the
   * 'lambda' array.
   *
   * @param k      The number of distinct primes to be generated.
   * @param lambda An array of integers representing the bit lengths of each
   *               prime number.
   * @throws IllegalArgumentException If the lambda array does not have 'k'
   * elements or if the sum
   *                                  of the bit lengths does not meet the
   *                                  key size requirements.
   */
  public GenRSA(int k, int[] lambda) throws IllegalArgumentException {
    initialise(k, lambda);
    eBitLength = keySize;
  }

  /**
   * Constructs a GenRSA object with an option to specify a smaller bit
   * length for 'e' (i.e., 1/4 of
   * modulus bit length). This constructor allows for the generation of RSA
   * keys with a modulus
   * derived from 'k' distinct primes, each having specified bit lengths, and
   * with a smaller 'e' for
   * specific applications.
   *
   * @param k        The number of distinct primes to be generated.
   * @param lambda   An array of integers representing the bit lengths of
   *                 each prime number.
   * @param isSmallE Flag to indicate whether a smaller 'e' should be used.
   * @throws IllegalArgumentException If the lambda array does not have 'k'
   * elements or if the sum
   *                                  of the bit lengths does not meet the
   *                                  key size requirements.
   */
  public GenRSA(int k, int[] lambda, boolean isSmallE) throws IllegalArgumentException {
    initialise(k, lambda);
    eBitLength = isSmallE ? keySize / 4 : keySize;
  }

  /**
   * Initialises the GenRSA object, setting its parameters based on the
   * provided number of primes
   * 'k' and their respective bit lengths 'lambda'.
   *
   * @param k      The number of distinct primes to be used.
   * @param lambda An array containing the bit lengths of each prime.
   * @throws IllegalArgumentException If the lambda array does not have 'k'
   * elements, or if the
   *                                  computed key size is not within the
   *                                  acceptable range.
   */
  public void initialise(int k, int[] lambda) throws IllegalArgumentException {
    if (lambda.length != k) {
      throw new IllegalArgumentException("Lambda array must have k elements.");
    }

    for (int bitLength : lambda) {
      keySize += bitLength;
    }
    if (!(keySize >= MINKEYSIZE && keySize <= MAXKEYSIZE && k > 1)) {
      throw new IllegalArgumentException(
        "Key size cannot be smaller than " + MINKEYSIZE + "bits or larger " +
          "than" + MAXKEYSIZE
          + "bits");
    }

    this.k = k;
    this.lambda = lambda;
  }

  /**
   * Generates an array of k distinct prime numbers based on the provided bit
   * lengths.
   *
   * @return An array of BigInteger, each representing a distinct prime number.
   */
  public BigInteger[] generatePrimeComponents() {
    BigInteger[] components = new BigInteger[k];
    for (int i = 0; i < k; i++) {
      components[i] = new BigInteger(lambda[i], this.certainty,
        new SecureRandom());
    }
    return components;
  }

  /**
   * Computes the Euler's totient function (φ) for an RSA modulus that is the
   * product of k distinct
   * prime numbers.
   *
   * @param components An array of BigInteger representing the distinct prime
   *                  numbers.
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
   * Computes the public exponent {@code e} for public key component in the
   * RSA Key pair.
   *
   * @param phi The result of Euler's totient function.
   * @return The public exponent {@code e}.
   */
  public BigInteger computeE(BigInteger phi) {
    BigInteger e = new BigInteger(eBitLength, new SecureRandom());
    while (e.compareTo(ONE) <= 0 || !phi.gcd(e).equals(ONE) || e.compareTo(phi) >= 0) {
      e = new BigInteger(eBitLength, new SecureRandom());
    }
    return e;
  }

  /**
   * Generates the RSA modulus by multiplying a given array of prime numbers.
   *
   * @param primes An array of BigInteger prime numbers.
   * @return The RSA modulus as a BigInteger, resulting from the product of
   * the prime numbers.
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
   * @return A {@code KeyPair} object containing the generated RSA public and
   * private keys.
   */
  public KeyPair generateKeyPair() {
    BigInteger[] primes = this.generatePrimeComponents();
    BigInteger N = genModulus(primes);
    BigInteger phi = computePhi(primes);
    BigInteger e = computeE(phi);
    /*
     * Computes the private exponent d for private key component in the RSA
     * Key pair.
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
   * Returns the certainty level used for prime number generation. The higher
   * the certainty, the
   * more certain it is that the generated numbers are prime.
   *
   * @return The certainty level for prime number generation.
   */
  public int getCertainty() {
    return this.certainty;
  }

}
