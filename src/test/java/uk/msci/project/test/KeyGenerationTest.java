package uk.msci.project.test;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.lang.reflect.Modifier;
import java.math.BigInteger;
import uk.msci.project.rsa.PublicKey;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import uk.msci.project.rsa.Key;


public class KeyGenerationTest {

  @Test
    // Test 1
    // Create abstract class that provides a foundational representation of an RSA key
    // Test key class to check if it is abstract
  void testAbstractKey() {
    Class<Key> key = Key.class;
    Assertions.assertTrue(Modifier.isAbstract(key.getModifiers()));
  }

  @Test
    // Test 2
    // Create a field representing the exponent of the key
    // and a method (getter) that returns the value of the field
  void testGetExponent() {
    BigInteger expectedExponent = new BigInteger("98765432109876543210");
    Key publicKey = new PublicKey(new BigInteger("98765432109876543210"));

    // Act
    BigInteger actualExponent = publicKey.getExponent();

    // Assert
    assertEquals(expectedExponent, actualExponent,
        "The getExponent method should return the correct exponent value");
  }


}
