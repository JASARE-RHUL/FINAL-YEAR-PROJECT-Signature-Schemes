package uk.msci.project.rsa;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.zip.DataFormatException;

import uk.msci.project.rsa.exceptions.InvalidDigestException;
import uk.msci.project.rsa.exceptions.InvalidSignatureTypeException;
import uk.msci.project.rsa.SigScheme;
import uk.msci.project.rsa.SignatureType;
import uk.msci.project.rsa.DigestFactory;
import uk.msci.project.rsa.SignatureFactory;
import uk.msci.project.rsa.Key;
import uk.msci.project.rsa.DigestType;

/**
 * This class is part of the Model component specific to digital signature
 * operations providing
 * methods to sign data and verify signatures.  It encapsulates the data and
 * the logic required to
 * keep track of a user initiated digital signature scheme.
 */
public class SignatureModel {

  /**
   * The current state of the model representing a tracked instance of a
   * signature scheme
   */
  SigScheme currentSignatureScheme;
  /**
   * The Key corresponding to the current Signature Scheme instance
   */
  Key key;

  /**
   * The type of to the current Signature Scheme instance
   */
  SignatureType currentType;

  /**
   * The type of hash function used in the signature scheme.
   */
  DigestType currentHashType = DigestType.SHA_256;

  /**
   * The size of the hash output in bytes.
   */
  int hashSize;

  /**
   * Indicator of whether the current signature scheme operates in provably
   * secure mode.
   */
  boolean isProvablySecure;

  boolean isRecoveryScheme;


  /**
   * Constructs a new {@code SignatureModel} without requiring an initial key
   * representative of the
   * fact that at program launch, the model does not have any state: until it
   * is initiated by the
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
    try {
      isRecoveryScheme = SignatureFactory.getRecoveryStatus(signatureType);
    } catch (InvalidSignatureTypeException e) {
      throw new RuntimeException(e);
    }
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
   * Sets the type of hash function to be used.
   *
   * @param hashType The type of hash function to be set.
   */
  public void setHashType(DigestType hashType) {
    this.currentHashType = hashType;
  }

  /**
   * Retrieves the type of hash function currently set in the model.
   *
   * @return The current hash function type.
   */
  public DigestType getHashType() {
    return currentHashType;
  }

  /**
   * Sets the size of the hash output in bytes.
   *
   * @param hashSize The size of the hash output in bytes to be set.
   * @throws IllegalArgumentException if the hash size is negative.
   */
  public void setHashSize(int hashSize) {
    if (hashSize < 0) {
      throw new IllegalArgumentException(
        "Hash size must be a non-negative integer");
    }
    this.hashSize = hashSize;
  }


  /**
   * Retrieves the size of the hash output in bits.
   *
   * @return The size of the hash output in bits.
   */
  public int getHashSize() {
    return hashSize;
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
   * Returns the key for corresponding to current signature scheme.
   *
   * @return The Key respective to the currently set signature scheme.
   */
  public Key getKey() {
    return key;
  }


  /**
   * Instantiates a signature scheme based on the current key and signature
   * type. Throws an
   * exception if either the key or the signature type is not set.
   *
   * @throws InvalidSignatureTypeException if the parameter passed
   * SignatureType is not valid or
   *                                       supported.
   */
  public void instantiateSignatureScheme()
    throws InvalidSignatureTypeException, NoSuchAlgorithmException,
    InvalidDigestException, NoSuchProviderException {
    if (key != null && currentType != null) {
      currentSignatureScheme =
        SignatureFactory.getSignatureScheme(currentType, key,
        isProvablySecure);
      try {
        currentSignatureScheme.setDigest(currentHashType, hashSize);
      } catch (IllegalArgumentException e) {
        throw new IllegalArgumentException(
          "Custom hash size must a positive integer that allows the minimum " +
            "bytes of padding to be incorporated");
      }

    } else {
      throw new IllegalStateException(
        "Both key and signature type need to be set before instantiating a " +
          "signature scheme");
    }
  }

  /**
   * Signs the given data using the current signature scheme.
   *
   * @param data The data to be signed.
   * @return A byte array representing the digital signature.
   * @throws IllegalStateException if the key or signature type is not set
   * before signing.
   * @throws DataFormatException   If signing process fails due to incorrect
   * format.
   */
  public byte[] sign(byte[] data) throws DataFormatException {
    if (currentSignatureScheme == null) {
      throw new IllegalStateException("Both key and signature type need to be" +
        " set before signing");
    }
    return currentSignatureScheme.sign(data);
  }

  /**
   * Verifies a signature against the provided data using the current
   * signature scheme.
   *
   * @param data      The data to be verified against the signature.
   * @param signature The signature to be verified.
   * @return {@code true} if the signature is valid, {@code false} otherwise.
   * @throws IllegalStateException if the key or signature type is not set
   * before verification.
   * @throws DataFormatException   If verification fails due to incorrect
   * format.
   */
  public boolean verify(byte[] data, byte[] signature) throws DataFormatException {
    if (currentSignatureScheme == null) {
      throw new IllegalStateException(
        "Both key and signature type need to be set before verification");
    }
    return currentSignatureScheme.verify(data, signature);
  }

  /**
   * Gets the non-recoverable portion of message as generated by the adjusted
   * sign method for
   * signature schemes with message recovery
   *
   * @return signing process initialised non-recoverable portion of message
   */
  public byte[] getNonRecoverableM() {
    return currentSignatureScheme.getNonRecoverableM();
  }

  /**
   * Gets recoverable portion of message as generated by the adjusted verify
   * method for signature
   * schemes with message recovery
   *
   * @return verification process initialised non-recoverable portion of message
   */
  public byte[] getRecoverableM() {
    return currentSignatureScheme.getRecoverableM();
  }


  /**
   * Indicates whether the signature scheme operates in provably secure mode.
   *
   * @return {@code true} if the signature scheme is operating in provably
   * secure mode, {@code
   * false} otherwise.
   */
  public boolean getProvablySecure() {
    return isProvablySecure;
  }

  /**
   * Sets whether the signature scheme should operate in provably secure mode.
   *
   * @param isProvablySecure A boolean flag to enable or disable provably
   *                         secure mode.
   */
  public void setProvablySecure(boolean isProvablySecure) {
    this.isProvablySecure = isProvablySecure;
  }


  /**
   * Retrieves the status indicating whether the currently tracked signature
   * scheme supports message recovery.
   *
   * @return true if the signature scheme is a message recovery scheme, false
   * otherwise.
   */
  boolean getRecoveryStatus() {
    return isRecoveryScheme;
  }
}
