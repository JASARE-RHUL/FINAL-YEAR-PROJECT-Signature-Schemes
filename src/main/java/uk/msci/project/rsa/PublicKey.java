package uk.msci.project.rsa;

import java.io.IOException;
import java.math.BigInteger;

/**
 * This class represents the public key derived from an RSA key pair.
 */
public class PublicKey extends Key {

  /**
   * Constructs public key by parsing a string representation (comma delimited modulus and exponent)
   * of the key. This constructor delegates the parsing to the superclass constructor.
   *
   * @param key The string representation of the public key.
   */
  public PublicKey(String key) {
    super(key);
  }

  /**
   * Constructs a public key with the given modulus and exponent.
   *
   * @param N The modulus part of the public key.
   * @param e The exponent part of the public key.
   */
  public PublicKey(BigInteger N, BigInteger e) {
    super(N, e);
  }
}

