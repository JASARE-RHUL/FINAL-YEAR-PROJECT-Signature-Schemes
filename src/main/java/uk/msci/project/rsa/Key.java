package uk.msci.project.rsa;


import java.math.BigInteger;

/**
 * This abstract class provides a foundational representation of an RSA key, encapsulating common
 * attributes and behaviors such as parsing, storing, and retrieving a key or its components. It
 * provides methods to load the key from a file or initialise it directly using a string
 * representation. This class is intended to be subclassed to create concrete (public or private)
 * key representations.
 */
public abstract class Key {

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
  public Key(BigInteger key) {
    this.exponent = key;
  }
  /**
   * Gets the exponent of this key.
   *
   * @return The exponent of this key.
   */
  public BigInteger getExponent() {
    return this.exponent;
  }
}
