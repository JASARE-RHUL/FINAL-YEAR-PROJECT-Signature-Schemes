package uk.msci.project.rsa;


import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.util.regex.Pattern;

/**
 * This abstract class provides a foundational representation of an RSA key, encapsulating common
 * attributes and behaviors such as parsing, storing, and retrieving a key or its components. It
 * provides methods to load the key from a file or initialise it directly using a string
 * representation. This class is intended to be subclassed to create concrete (public or private)
 * key representations.
 */
public abstract class Key {


  /**
   * The string representation of the key
   */
  protected String keyValue;

  /**
   * Component part of the key comprising the modulus
   */
  protected BigInteger modulus;

  /**
   * Component part of the key comprising the exponent
   */
  protected BigInteger exponent;

  /**
   * Constructs key using a comma-delimited string representation of the key containing the modulus
   * followed by the exponent. This constructor initialises the key's value and parses the modulus
   * and exponent.
   *
   * @param key The string representation of the key.
   */
  public Key(String key) {
    parseKeyValue(key);
  }


  /**
   * Validates the modulus and exponent components of the public key to ensure they are not null and
   * are positive integers.
   *
   *
   * @param modulus  the modulus component of the public key.
   * @param exponent the exponent component of the public key.
   * @return {@code true} if both the modulus and exponent are valid.
   * @throws NullPointerException     if either the modulus or the exponent is {@code null}.
   * @throws IllegalArgumentException if either the modulus or the exponent is less than or equal to
   *                                  0.
   */
  protected void checkValidKeyComponents(BigInteger modulus, BigInteger exponent) {
    if (modulus == null || exponent == null) {
      throw new NullPointerException(
          "Public Key cannot be constructed with a null component");
    }

    if (modulus.compareTo(BigInteger.ZERO) <= 0 || exponent.compareTo(BigInteger.ZERO) <= 0) {
      throw new IllegalArgumentException(
          "Public Key cannot be constructed with a non positive modulus or exponent");
    }

  }

  /**
   * Constructs an RSA key with the given modulus and exponent.
   *
   * @param modulus  The modulus part of the key.
   * @param exponent The exponent part of the key.
   */
  public Key(BigInteger modulus, BigInteger exponent) {
    checkValidKeyComponents(modulus, exponent);
    this.modulus = modulus;
    this.exponent = exponent;
  }

  /**
   * Parses the string representation of the key to extract the modulus and exponent.
   *
   * @param keyValue The string representation of the key.
   */
  protected void parseKeyValue(String keyValue) {
    if (!keyValue.contains(",")) {
      throw new IllegalArgumentException("Key value must contain a comma as the delimiter");
    }
    this.keyValue = keyValue;
    String[] keyArray = keyValue.split(",");

    checkValidKeyComponents(modulus, exponent);
    this.modulus = new BigInteger(keyArray[0]);
    this.exponent = new BigInteger(keyArray[1]);
  }


  /**
   * Gets the exponent of this key.
   *
   * @return The exponent of this key.
   */
  public BigInteger getExponent() {
    return this.exponent;
  }

  /**
   * Gets the modulus of this key.
   *
   * @return The modulus of this key.
   */
  public BigInteger getModulus() {
    return this.modulus;
  }
}

