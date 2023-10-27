package uk.msci.project.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import org.junit.jupiter.api.Test;
import uk.msci.project.rsa.GenRSA;
import uk.msci.project.rsa.Key;
import uk.msci.project.rsa.PrivateKey;
import uk.msci.project.rsa.PublicKey;

public class GenRSATest {

  @Test
    // Test 1
    // Create a constructor for a newly created GenRSATest class that enables a generation process to be
    // initialised for generating a key with a specified key size.
    // Enable the key size to be retrieved through a getter.
  void testKeySize() {
    int expectedKeySize = 1024;
    GenRSA genRSA = new GenRSA(1024);

    // Assert
    assertEquals(expectedKeySize, genRSA.getKeySize(),
        "The getKeySize method should return the correct key size");
  }

  @Test
    // Test 2
    // Enable the GenRSA constructor to only permit positive integers
    // between 1024 and 7680 as valid key sizes.
  void testInvalidKeySize() {

    // key size < upper interval
    assertThrows(IllegalArgumentException.class, () -> new GenRSA(512),
        "Should throw an exception when key size is not in the positive integer Interval [1024, 7680]");

    // key size > upper interval
    assertThrows(IllegalArgumentException.class, () -> new GenRSA(27000),
        "Should throw an exception when key size is not in the positive integer Interval [1024, 7680]");

    // key size < upper interval (extreme)
    assertThrows(IllegalArgumentException.class, () -> new GenRSA(9),
        "Should throw an exception when key size is not in the positive integer Interval [1024, 7680]");
    // key size > upper interval (extreme)
    assertThrows(IllegalArgumentException.class, () -> new GenRSA(99999999),
        "Should throw an exception when key size is not in the positive integer Interval [1024, 7680]");
  }

  @Test
    // Test 4
  void testValidKeySize() {

    // boundary case
    GenRSA genRSA = new GenRSA(7680);
    assertEquals(7680, genRSA.getKeySize(),
        "The getKeySize method should return the correct key size");
    GenRSA genRSA2 = new GenRSA(2048);
    assertEquals(2048, genRSA2.getKeySize(),
        "The getKeySize method should return the correct key size");
    GenRSA genRSA3 = new GenRSA(3072);
    assertEquals(3072, genRSA3.getKeySize(),
        "The getKeySize method should return the correct key size");
    GenRSA genRSA4 = new GenRSA(4096);
    assertEquals(4096, genRSA4.getKeySize(),
        "The getKeySize method should return the correct key size");
  }

  @Test
    // Test 5
    // Create a method,generatePrimeComponents that generates two probable primes
    // intended to comprise the prime factors of the modulus N
  void testGeneratePrimeComponents() {
    GenRSA genRSA = new GenRSA(1024);
    BigInteger[] primeComponents = genRSA.generatePrimeComponents();
    assertEquals(75, genRSA.getCertainty());
    assertTrue(primeComponents[0].isProbablePrime(genRSA.getCertainty()));
    assertTrue(primeComponents[1].isProbablePrime(genRSA.getCertainty()));
  }

  @Test
    // Test 6
    // Create a method,computePhi intended to compute the
    // Computes the Euler's totient function of the Modulus N
  void testComputePhi() {
    GenRSA genRSA = new GenRSA(1024);
    BigInteger[] primeComponents = genRSA.generatePrimeComponents();
    BigInteger p = primeComponents[0];
    BigInteger q = primeComponents[1];
    BigInteger expectedPhi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
    // Act
    BigInteger actualPhi = genRSA.computePhi(p, q);
    // Assert
    assertEquals(expectedPhi, actualPhi,
        "The computePhi method should return the correct Euler's totient function result");
  }


}
