package uk.msci.project.rsa;

import java.util.zip.DataFormatException;

/**
 * This class is part of the Model component specific to digital signature operations providing
 * methods to sign data and verify signatures.  It encapsulates the data and the logic required to
 * keep track of a user initiated digital signature scheme.
 */
public class SignatureModel {

  /**
   * The current state of the model representing a tracked instance of a signature scheme
   */
  private SigScheme currentSignatureScheme;
  /**
   * The Key corresponding to the current Signature Scheme instance
   */
  private Key key;

  /**
   * The type of to the current Signature Scheme instance
   */
  private SignatureType currentType;


  /**
   * Constructs a new {@code SignatureModel} without requiring an initial key representative of the
   * fact that at program launch, the model does not have any state: until it is initiated by the
   * user
   */
  public SignatureModel() {
  }

  /**
   * Sets the type of signature to be used.
   *
   * @param signatureType The type of signature to be set.
   */
  public void setSignatureType(SignatureType signatureType) {
    this.currentType = signatureType;
  }

  /**
   * Returns the current type of signature set in the model.
   *
   * @return The current type of signature.
   */
  public SignatureType getSignatureType() {
    return currentType;
  }

  /**
   * Sets the key to be used in the signature scheme.
   *
   * @param key The key to be set for the signature operations.
   */
  public void setKey(Key key) {
    this.key = key;
  }

  /**
   * Instantiates a signature scheme based on the current key and signature type. Throws an
   * exception if either the key or the signature type is not set.
   */
  public void instantiateSignatureScheme() throws InvalidSignatureTypeException {
    if (key != null && currentType != null) {
      currentSignatureScheme = SignatureFactory.getSignatureScheme(currentType, key);
    } else {
      throw new IllegalStateException(
          "Both key and signature type need to be set before instantiating a signature scheme");
    }
  }
  /**
   * Signs the given data using the current signature scheme.
   *
   * @param data The data to be signed.
   * @return A byte array representing the digital signature.
   * @throws IllegalStateException if the key or signature type is not set before signing.
   */
  public byte[] sign(byte[] data) throws DataFormatException {
    if (currentSignatureScheme == null) {
      throw new IllegalStateException("Both key and signature type need to be set before signing");
    }
    return currentSignatureScheme.sign(data);
  }



}
