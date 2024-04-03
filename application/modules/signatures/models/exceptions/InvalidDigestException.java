package uk.msci.project.rsa.exceptions;

/**
 * Exception thrown when an invalid digest type is specified.
 */
public class InvalidDigestException extends Exception {

  /**
   * Constructs a new InvalidDigestException with the specified detail message.
   *
   * @param message the detail message.
   */
  public InvalidDigestException(String message) {
    super(message);
  }

  /**
   * Constructs a new InvalidSignatureTypeException.
   */
  public InvalidDigestException() {
    super();
  }
}
