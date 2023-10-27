package uk.msci.project.rsa;

public class GenRSA {

  /**
   * The size of the key to be generated.
   */
  private int keySize;

  /**
   * Constructs a {@code GenRSA} object with a specified key size.
   *
   * @param size The desired bit length of the RSA keys.
   * @throws IllegalArgumentException if the specified key size is invalid.
   */
  public GenRSA(int size) throws IllegalArgumentException {
      this.keySize = size;
  }

  /**
   * Returns the size of the key to be generated.
   *
   * @return The bit length of the RSA keys.
   */
  public int getKeySize() {
    return this.keySize;
  }

}
