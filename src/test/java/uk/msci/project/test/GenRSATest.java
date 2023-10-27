package uk.msci.project.test;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.math.BigInteger;
import org.junit.jupiter.api.Test;
import uk.msci.project.rsa.GenRSA;
import uk.msci.project.rsa.Key;
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

}
