package uk.msci.project.rsa;

/**
 * Represents the result of a signature verification process. This class encapsulates information
 * about whether the signature is valid, the recovered message (if any), and the concrete signature
 * scheme used.
 */
public class SignatureRecovery {

  /**
   * Indicates whether the signature is valid.
   */
  private final boolean isValid;

  /**
   * The recovered message from the signature. This may be null if the signature is invalid or if no
   * message recovery is part of the signature scheme.
   */
  private final byte[] recoveredMessage;

  /**
   * The concrete class of the signature scheme used for the verification.
   */
  private final Class<?> sigScheme;

  /**
   * Constructs a SignatureRecovery object with the specified validity, recovered message, and
   * signature scheme.
   *
   * @param isValid          Indicates whether the signature is valid.
   * @param recoveredMessage The recovered message. Can be null if the signature is invalid or the
   *                         scheme does not support message recovery.
   * @param sigScheme        The class of the signature scheme used for verification.
   */
  public SignatureRecovery(boolean isValid, byte[] recoveredMessage, Class<?> sigScheme) {
    this.isValid = isValid;
    this.recoveredMessage = recoveredMessage;
    this.sigScheme = sigScheme;
  }

  /**
   * Returns whether the signature is valid.
   *
   * @return True if the signature is valid, false otherwise.
   */
  public boolean isValid() {
    return isValid;
  }

  /**
   * Retrieves the recovered message from the signature.
   *
   * @return A byte array containing the recovered message, or null if not applicable.
   */
  public byte[] getRecoveredMessage() {
    return recoveredMessage;
  }

  /**
   * Returns the concrete signature scheme class used for verification.
   *
   * @return The Class object representing the signature scheme used.
   */
  public Class<?> getConcreteScheme() {
    return sigScheme;
  }
}
