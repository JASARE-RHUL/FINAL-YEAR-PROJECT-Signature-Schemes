package uk.msci.project.rsa;


import java.io.File;
import java.io.IOException;
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
   * Component part of the key comprising the modulus
   */
  protected BigInteger modulus;

  /**
   * Component part of the key comprising the exponent
   */
  protected BigInteger exponent;



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

