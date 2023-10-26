package uk.msci.project.rsa;

import java.io.IOException;
import java.math.BigInteger;

/**
 * This class represents the public key derived from an RSA key pair.
 */
public class PublicKey extends Key {

  /**
   * Constructs a public key with the given modulus and exponent.
   *
   * @param N The modulus part of the public key.
   * @param e The exponent part of the public key.
   */
  public PublicKey(BigInteger N, BigInteger e) {
    this.modulus = N;
    this.exponent = e;
  }
}

