package uk.msci.project.rsa;


import java.io.IOException;

/**
 * This class is part of the Model component specific to the RSA key generation process. It
 * encapsulates the data and the logic required to keep track of a user initiated key generation
 * process
 */
public class GenModel {

  /**
   * The number of prime factors to be used in modulus generation.
   */
  private int k;

  /**
   * An array representing the bit size for each prime factor.
   */
  private int[] lambda;

  /**
   * The current state of the model representing a tracked instance of GenRSA
   */
  private GenRSA currentGen;

  /**
   * The Key pair corresponding to the current Key Generation instance
   */
  private KeyPair generatedKeyPair;


  /**
   * Constructor for GenModel. This initialises the model which will be bound to the runtime
   * behavior of the signature program. At the point of launch, the model does not have any state
   * until it is initiated by the user.
   */
  public GenModel() {
  }

  /**
   * Sets the key parameters for RSA key generation.
   *
   * @param k      The number of prime factors in the modulus.
   * @param lambda An array of integers representing the bit sizes for each prime factor.
   */
  public void setKeyParameters(int k, int[] lambda) {
    this.k = k;
    this.lambda = lambda;
  }

  /**
   * Initialises the state i.e., the current Generation process to be tracked.
   */
  public void setGen() {
    this.currentGen = new GenRSA(k, lambda);
  }

  /**
   * Generates an RSA key with using the currently tracked generation process.
   *
   * @throws IllegalStateException if key parameters are not set before key generation.
   */
  public void generateKey() {
    if (currentGen == null) {
      throw new IllegalStateException("Key Size needs to be set before a key can be generated");
    }
    generatedKeyPair = currentGen.generateKeyPair();
  }

  /**
   * Gets the freshly generated key pair
   *
   * @return KeyPair representing the generated public and private key
   */
  public KeyPair getGeneratedKeyPair() {
    KeyPair keyPair = generatedKeyPair;
    return keyPair;
  }

  /**
   * Exports the generated RSA key pair to files.
   *
   * @throws IOException           if there is an error during the export process.
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
