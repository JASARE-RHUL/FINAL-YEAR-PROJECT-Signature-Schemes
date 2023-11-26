package uk.msci.project.rsa;

import java.math.BigInteger;

/**
 * This class represents a pair of associated cryptographic keys that are generated together and
 * mathematically related: a public key and a private key. Instances of this class are used to group
 * a public key with its corresponding private key.
 */
public class KeyPair {

  /**
   * The public key of the key pair.
   */
  private final PublicKey publicKey;

  /**
   * The private key of the key pair.
   */
  private final PrivateKey privateKey;

  /**
   * Constructs a {@code KeyPair} with the specified public and private keys.
   *
   * @param publicKey  the public key.
   * @param privateKey the private key.
   */
  public KeyPair(PublicKey publicKey, PrivateKey privateKey) {
    this.publicKey = publicKey;
    this.privateKey = privateKey;
  }

  /**
   * Returns the public key from this key pair.
   *
   * @return the public key.
   */
  public PublicKey getPublicKey() {
    return publicKey;
  }

  /**
   * Returns the private key from this key pair.
   *
   * @return the private key.
   */
  public PrivateKey getPrivateKey() {
    return privateKey;
  }
}
