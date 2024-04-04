package uk.msci.project.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;

import org.junit.jupiter.api.Test;
import uk.msci.project.rsa.GenRSA;
import uk.msci.project.rsa.KeyPair;

class GenRSATest {

  @Test
    // Test 1
    // Create a constructor for a newly created GenRSATest class that enables
    // a generation process to be
    // initialised for generating a key with a specified key size.
    // Enable the key size to be retrieved through a getter.
  void testKeySize() {
    int expectedKeySize = 1024;
    GenRSA genRSA = new GenRSA(2, new int[]{512, 512});

    // Assert
    assertEquals(expectedKeySize, genRSA.getKeySize(),
      "The getKeySize method should return the correct key size");
  }

  @Test
    // Test 2
    // Enable the GenRSA constructor to only permit positive integers
    // between 1024 and 7680 as valid key sizes.
  void testInvalidKeySize() {
    int k = 2;
    // key size < upper interval
    assertThrows(IllegalArgumentException.class, () -> new GenRSA(k,
        new int[]{256, 256}),
      "Should throw an exception when key size is not in the positive integer" +
        " Interval [1024, 7680]");

    // key size > upper interval
    assertThrows(IllegalArgumentException.class, () -> new GenRSA(k,
        new int[]{13500, 13500}),
      "Should throw an exception when key size is not in the positive integer" +
        " Interval [1024, 7680]");

    // key size < upper interval (extreme)
    assertThrows(IllegalArgumentException.class, () -> new GenRSA(k,
        new int[]{5, 4}),
      "Should throw an exception when key size is not in the positive integer" +
        " Interval [1024, 7680]");
    // key size > upper interval (extreme)
    assertThrows(IllegalArgumentException.class, () -> new GenRSA(k,
        new int[]{99999, 888888}),
      "Should throw an exception when key size is not in the positive integer" +
        " Interval [1024, 7680]");
  }


  @Test
  void testValidKeySize() {
    int k = 2; // Number of primes

    // Valid lambda arrays
    int[] lambda7680 = {3840, 3840}; // Sum is 7680
    GenRSA genRSA = new GenRSA(k, lambda7680);
    assertEquals(7680, genRSA.getKeySize(),
      "The getKeySize method should return the correct key size");

    int[] lambda2048 = {1024, 1024}; // Sum is 2048
    GenRSA genRSA2 = new GenRSA(k, lambda2048);
    assertEquals(2048, genRSA2.getKeySize(),
      "The getKeySize method should return the correct key size");

    GenRSA genRSA3 = new GenRSA(k, new int[]{1536, 1536});
    assertEquals(3072, genRSA3.getKeySize(),
      "The getKeySize method should return the correct key size");

    GenRSA genRSA4 = new GenRSA(k, new int[]{2048, 2048});
    assertEquals(4096, genRSA4.getKeySize(),
      "The getKeySize method should return the correct key size");
  }


  @Test
    // Test 5
    // Create a method,generatePrimeComponents that generates two probable
    // primes
    // intended to comprise the prime factors of the modulus N
  void testGeneratePrimeComponents() {
    int k = 2; // Number of primes
    int[] lambda = {512, 512};
    GenRSA genRSA = new GenRSA(k, lambda);
    BigInteger[] primeComponents = genRSA.generatePrimeComponents();

    assertEquals(75, genRSA.getCertainty(),
      "The certainty level should match the default certainty level.");

// Check that each generated component is a probable prime
    for (BigInteger prime : primeComponents) {
      assertTrue(prime.isProbablePrime(genRSA.getCertainty()),
        "Each component should be a probable prime with the given certainty.");
    }

  }

  @Test
    // Test 6
    // Create a method,computePhi intended to compute the
    // Computes the Euler's totient function of the Modulus N
  void testComputePhi() {
    int k = 3;
    int[] lambda = {341, 341,
      342};
    GenRSA genRSA = new GenRSA(k, lambda);
    BigInteger[] primeComponents = genRSA.generatePrimeComponents();

    BigInteger expectedPhi = BigInteger.ONE;
    for (BigInteger prime : primeComponents) {
      expectedPhi = expectedPhi.multiply(prime.subtract(BigInteger.ONE));
    }

    // Act
    BigInteger actualPhi = genRSA.computePhi(primeComponents);

    // Assert
    assertEquals(expectedPhi, actualPhi,
      "The computePhi method should return the correct Euler's totient " +
        "function result for multiple primes.");
  }


  @Test
    // Test 7
    // Create a method, computeE intended to compute the
    // public exponent {@code e} for public key component in the RSA Key pair
    // Tests that e and euler's totient are co prime
  void testComputeE() {
    int k = 3; // Example for three prime factors
    int[] lambda = {341, 341, 342}; // Example bit lengths
    GenRSA genRSA = new GenRSA(k, lambda);
    BigInteger[] primeComponents = genRSA.generatePrimeComponents();
    BigInteger phi = genRSA.computePhi(primeComponents);
    BigInteger e = genRSA.computeE(phi);
    assertEquals(BigInteger.ONE, e.gcd(phi), "The public exponent 'e' and " +
      "'phi' should be coprime");
  }

  @Test
  void testComputeEIsGreaterThanOne() {
    int k = 3;
    int[] lambda = {341, 341, 342};
    GenRSA genRSA = new GenRSA(k, lambda);
    BigInteger[] primeComponents = genRSA.generatePrimeComponents();
    BigInteger phi = genRSA.computePhi(primeComponents);
    BigInteger e = genRSA.computeE(phi);

    assertTrue(e.compareTo(BigInteger.ONE) > 0,
      "The public exponent 'e' should be greater than one");
  }

  @Test
  void testComputeEIsLessThanPhi() {
    int k = 3;
    int[] lambda = {341, 341, 342};
    GenRSA genRSA = new GenRSA(k, lambda);
    BigInteger[] primeComponents = genRSA.generatePrimeComponents();
    BigInteger phi = genRSA.computePhi(primeComponents);
    BigInteger e = genRSA.computeE(phi);

    assertTrue(e.compareTo(phi) < 0, "The public exponent 'e' should be less " +
      "than 'phi'");
  }

//
//  @Test
//    // Test 10
//    // Create a method, generateKeyPair that fulfils the generation of an
//    RSA Key pair
//  void testGenerateKeyPair() {
//    GenRSA genRSA = new GenRSA(1024);
//    BigInteger[] keyPair = genRSA.generateKeyPair();
//    BigInteger N = keyPair[0];
//    BigInteger p = keyPair[1];
//    BigInteger q = keyPair[2];
//
//
//    assertNotNull(keyPair, "The generateKeyPair method should not return
//    null");
//    assertEquals(5, keyPair.length,
//        "The generateKeyPair method should return an array of 5 BigInteger
//        components");
//
//    assertEquals(p.multiply(q), N,
//        "The modulus N should be the product of two prime numbers p and q");
//
//    BigInteger phi = genRSA.computePhi(p, q);
//    BigInteger e = keyPair[3];
//    BigInteger d = keyPair[4];
//    assertTrue(e.compareTo(BigInteger.ONE) > 0 && e.compareTo(phi) < 0, "1
//    < e < phi(N) should be true");
//    assertEquals(BigInteger.ONE, e.gcd(phi), "gcd(e, phi(N)) should be 1");
//    assertEquals(e.modInverse(phi), d, "d should be the modular
//    multiplicative inverse of e modulo phi(N)");
//  }

  @Test
    // Test 11
    // Create a method, generateKeyPair that fulfils the generation of an RSA
    // Key pair
    // Refactor the return of key components into dedicated key classes,
    // Private and Public key comprising a Key Pair
    //Tests that the modulus does not differ between the public and private key
  void testGenerateKeyPair2() {
    int k = 3;
    int[] lambda = {341, 341, 342};
    GenRSA genRSA = new GenRSA(k, lambda);
    KeyPair keyPair = genRSA.generateKeyPair();
    BigInteger pubKeyModulus = keyPair.getPublicKey().getModulus();

    assertEquals(pubKeyModulus, keyPair.getPrivateKey().getModulus());
    BigInteger expectedModulus = BigInteger.ONE;
    for (BigInteger prime : keyPair.getPrivateKey().getPrimes()) {
      expectedModulus = expectedModulus.multiply(prime);
    }
    assertEquals(expectedModulus, pubKeyModulus,
      "The modulus N should be the product of its prime components");

    assertNotNull(keyPair, "The generateKeyPair method should not return null");

    BigInteger phi = keyPair.getPrivateKey().getPhi();
    BigInteger e = keyPair.getPrivateKey().getE();
    BigInteger d = keyPair.getPrivateKey().getExponent();
    assertTrue(e.compareTo(BigInteger.ONE) > 0 && e.compareTo(phi) < 0,
      "1 < e < phi(N) should be true");
    assertEquals(BigInteger.ONE, e.gcd(phi), "gcd(e, phi(N)) should be 1");
    assertEquals(e.modInverse(phi), d,
      "d should be the modular multiplicative inverse of e modulo phi(N)");
  }


}
