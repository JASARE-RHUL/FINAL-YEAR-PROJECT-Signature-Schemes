package uk.msci.project.rsa.exceptions;

/**
 * Exception thrown when an invalid signature type is specified.
 */
public class InvalidSignatureTypeException extends Exception {

  /**
   * Constructs a new InvalidSignatureTypeException with the specified detail message.
   *
   * @param message the detail message.
   */
  public InvalidSignatureTypeException(String message) {
    super(message);
  }

  /**
   * Constructs a new InvalidSignatureTypeException.
   */
  public InvalidSignatureTypeException() {
    super();
  }
}
