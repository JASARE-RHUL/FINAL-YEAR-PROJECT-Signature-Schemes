package uk.msci.project.rsa;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;

/**
 * This class represents the private key derived from an RSA key pair.
 */
public class PrivateKey extends Key {

  private BigInteger p;
  private BigInteger q;
  private BigInteger phi;
  private BigInteger e;


  /**
   * Constructs private key by parsing a string representation of the key, containing the modulus
   * followed by the exponent. This constructor delegates the parsing to the superclass
   * constructor.
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
   * Constructs a public key with the given modulus and exponent whilst also encapsulating the
   * auxiliary components used in the computation of the private exponent, d.
   *
   * @param N   The modulus part of the private key.
   * @param p   The first prime factor of the modulus.
   * @param q   The second prime factor of the modulus.
   * @param phi The result of Euler's totient function.
   * @param e   The public exponent.
   * @param d   The private exponent.
   */
  public PrivateKey(BigInteger N, BigInteger p, BigInteger q, BigInteger phi, BigInteger e,
      BigInteger d) {
    super(N, d);
    this.p = p;
    this.q = q;
    this.phi = phi;
    this.e = e;
  }

  /**
   * Constructs a private key by first importing the key from a file and then parsing resulting
   * string. This constructor delegates the file reading and parsing to the superclass constructor.
   *
   * @param keyFile The file from which to read the private key.
   * @throws IOException If an I/O error occurs while reading the key file.
   */
  public PrivateKey(File keyFile) throws IOException {
    super(keyFile);
  }

  /**
   * Retrieves the first prime factor of the modulus.
   *
   * @return The first prime factor of the modulus.
   */
  public BigInteger getP() {
    return this.p;
  }

  /**
   * Retrieves the second prime factor of the modulus.
   *
   * @return The second prime factor of the modulus.
   */
  public BigInteger getQ() {
    return this.q;
  }

  /**
   * Retrieves the result of Euler's totient function.
   *
   * @return The result of Euler's totient function.
   */
  public BigInteger getPhi() {
    return this.phi;
  }

  /**
   * Retrieves the public exponent.
   *
   * @return The public exponent.
   */
  public BigInteger getE() {
    return this.e;
  }

}

