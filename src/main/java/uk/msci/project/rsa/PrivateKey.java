package uk.msci.project.rsa;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;

/**
 * This class represents the private key derived from an RSA key pair.
 */
public class PrivateKey extends Key {

  /**
   * Constructs private key by parsing a string representation (comma delimited modulus and exponent)
   * of the key. This constructor delegates the parsing to the superclass constructor.
   *
   * @param key The string representation of the private key.
   */
  public PrivateKey(String key) {
    super(key);
  }

  /**
   * Constructs a public key with the given modulus and exponent.
   *
   * @param N The modulus part of the private key.
   * @param d The exponent part of the private key.
   */
  public PrivateKey(BigInteger N, BigInteger d) {
    super(N, d);
  }

  /**
   * Constructs a private key by first importing the key from a file and then parsing resulting string.
   * This constructor delegates the file reading and parsing to the superclass constructor.
   *
   * @param keyFile The file from which to read the private key.
   * @throws IOException If an I/O error occurs while reading the key file.
   */
  public PrivateKey(File keyFile) throws IOException {
    super(keyFile);
  }
}

