package uk.msci.project.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

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

}
