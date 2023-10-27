package uk.msci.project.test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.util.EmptyStackException;
import uk.msci.project.rsa.Key2;
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
    Key publicKey = new PublicKey(new BigInteger("776545678988777"),
        new BigInteger("98765432109876543210"));

    BigInteger actualExponent = publicKey.getExponent();

    // Assert
    assertEquals(expectedExponent, actualExponent,
        "The getExponent method should return the correct exponent value");
  }

  @Test
    // Test 3
    // Create a field representing the modulus of the key
    // and a method (getter) that returns the value of the field
  void testGetModulus() {
    BigInteger expectedN = new BigInteger("7645433344443333");
    Key publicKey = new PublicKey(new BigInteger("7645433344443333"),
        new BigInteger("43456564545554"));

    BigInteger actualN = publicKey.getModulus();

    // Assert
    assertEquals(expectedN, actualN,
        "The getModulus method should return the correct Modulus value");
  }

  @Test
    // Test 4
    // Test that setting any component of key to negative/null value throws an appropriate exception
  void testNegativeKeyValue() {

    // Define some test cases
    BigInteger[] modulusTestCases = {
        new BigInteger("12345678901234567890"),
        BigInteger.ZERO,
        new BigInteger("-12345678901234567890")
    };

    BigInteger[] exponentTestCases = {
        new BigInteger("98765432109876543210"),
        BigInteger.ZERO,
        new BigInteger("-98765432109876543210")
    };

    // Positive case - both modulus and exponent are positive
    assertDoesNotThrow(() -> new PublicKey(modulusTestCases[0], exponentTestCases[0]),
        "PublicKey should accept positive modulus and exponent");

    // Edge case - modulus or exponent is zero
    assertThrows(IllegalArgumentException.class,
        () -> new PublicKey(modulusTestCases[1], exponentTestCases[0]),
        "PublicKey should not accept modulus equal to zero");

    assertThrows(IllegalArgumentException.class,
        () -> new PublicKey(modulusTestCases[0], exponentTestCases[1]),
        "PublicKey should not accept exponent equal to zero");

    // Negative case - modulus or exponent is negative
    assertThrows(IllegalArgumentException.class,
        () -> new PublicKey(modulusTestCases[2], exponentTestCases[0]),
        "PublicKey should not accept negative modulus");

    assertThrows(IllegalArgumentException.class,
        () -> new PublicKey(modulusTestCases[0], exponentTestCases[2]),
        "PublicKey should not accept negative exponent");

    // Test for null values
    assertThrows(NullPointerException.class, () -> new PublicKey(null, exponentTestCases[0]),
        "PublicKey should not accept null modulus");

    assertThrows(NullPointerException.class, () -> new PublicKey(null, null),
        "PublicKey should not accept null modulus");

    assertThrows(NullPointerException.class, () -> new PublicKey(modulusTestCases[0], null),
        "PublicKey should not accept null exponent");

  }

  @Test
  // Test 5
  // Create a constructor that enables a key to be parsed from a string input
  // Test that the key can be constructed with a valid key input of a comma
  // seperated modulus and exponent
  public void testKeyWithStringValidInput() {
    String input = "23456788,897654";
    Key key = new PublicKey(input);

    assertEquals(new BigInteger("23456788"), key.getModulus(),
        "Modulus should be correctly parsed and set");
    assertEquals(new BigInteger("897654"), key.getExponent(),
        "Exponent should be correctly parsed and set");

  }

  @Test
  // Test 6
  // Test that the key cannot be constructed with an incorrectly formatted String representation
  public void testKeyWithStringInvalidDelimiter() {
    String input = "123456789;987654321";
    assertThrows(IllegalArgumentException.class, () -> new PublicKey(input),
        "Should throw an exception when the wrong delimiter e.g., not a comma is used");
  }

  @Test
  // Test 7
  // Test that the key cannot be constructed with an incorrectly formatted String
  // representation in the general case ,rather than on an ad hoc basis as in test 6
  public void testKeyWithStringFormat() {
    String input = "123456789,";
    assertThrows(IllegalArgumentException.class, () -> new PublicKey(input),
        "Should throw an exception for missing values");
    assertThrows(NullPointerException.class, () -> new PublicKey(null),
        "Should throw an exception for null input");

    String nonNumber = "notANumber,987654321";
    assertThrows(IllegalArgumentException.class, () -> new PublicKey(nonNumber),
        "Should throw an exception for non-numeric input");
  }


}

