package uk.msci.project.rsa;

import uk.msci.project.rsa.KeyPair;
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
    this.currentGen = new GenRSA(this.k, this.lambda);
  }

  /**
   * Generates an RSA key with usint the currently tracked generation processs.
   *
   * @throws IllegalStateException if key parameters are not set before key generation.
   */
  public void generateKey() {
    if (currentGen == null) {
      throw new IllegalStateException("Key Size needs to be set before a key can be generated");
    }
    generatedKeyPair = currentGen.generateKeyPair();
  }


}
