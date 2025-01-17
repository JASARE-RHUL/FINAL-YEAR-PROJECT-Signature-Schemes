package uk.msci.project.rsa;


import java.io.IOException;

import uk.msci.project.rsa.GenRSA;
import uk.msci.project.rsa.GenView;
import uk.msci.project.rsa.KeyPair;


/**
 * This class is part of the Model component specific to the RSA key
 * generation module in the
 * application, handling the data and logic associated with RSA key
 * generation. This includes
 * maintaining the state of the key generation process, tracking parameters,
 * and managing the
 * execution of key generation in standard modea. The class provides
 * functionalities for initiating
 * key generation, and exporting generated keys,
 */
public class GenModel {

  /**
   * The number of prime factors to be used in modulus generation.
   */
  int k;

  /**
   * An array representing the bit size for each prime factor.
   */
  int[] lambda;

  /**
   * The current state of the model representing a tracked instance of GenRSA
   */
  GenRSA currentGen;

  /**
   * The Key pair corresponding to the current Key Generation instance
   */
  KeyPair generatedKeyPair;


  /**
   * Constructor for GenModel. This initialises the model which will be bound
   * to the runtime
   * behavior of the signature program. At the point of launch, the model
   * does not have any state
   * until it is initiated by the user.
   */
  public GenModel() {
  }

  /**
   * Sets the key parameters for RSA key generation.
   *
   * @param k      The number of prime factors in the modulus.
   * @param lambda An array of integers representing the bit sizes for each
   *               prime factor.
   */
  public void setKeyParameters(int k, int[] lambda) {
    this.k = k;
    this.lambda = lambda;
  }


  /**
   * Initialises the state of the RSA key generation process. This method
   * sets up the current
   * generation process with the specified parameters for the number of
   * primes and their bit
   * lengths. It also allows for the option to use a smaller exponent 'e' in
   * the RSA key
   * generation.
   *
   * @param isSmallE A boolean flag indicating whether a smaller 'e' should
   *                 be used in the
   *                 generation process. If true, a smaller 'e' is used. If
   *                 false, a standard size
   *                 'e' is used.
   */
  public void setGen(boolean isSmallE) {
    this.currentGen = isSmallE ? new GenRSA(k, lambda, true) : new GenRSA(k,
      lambda);
  }


  /**
   * Generates an RSA key with using the currently tracked generation process.
   *
   * @throws IllegalStateException if key parameters are not set before key
   * generation.
   */
  public void generateKey() {
    if (currentGen == null) {
      throw new IllegalStateException("Key Size needs to be set before a key " +
        "can be generated");
    }
    generatedKeyPair = currentGen.generateKeyPair();
  }

  /**
   * Gets the freshly generated key pair
   *
   * @return KeyPair representing the generated public and private key
   */
  public KeyPair getGeneratedKeyPair() {
    return generatedKeyPair;
  }

  /**
   * Exports the generated RSA key pair to respective files.
   *
   * @throws IOException           if there is an error during the export
   * process.
   * @throws IllegalStateException if no key has been generated yet.
   */
  public void export() throws IOException {
    if (generatedKeyPair == null) {
      throw new IllegalStateException("No key has been generated yet.");
    }
    generatedKeyPair.getPrivateKey().exportKey("key.rsa");
    generatedKeyPair.getPublicKey().exportKey("publicKey.rsa");
  }


}
