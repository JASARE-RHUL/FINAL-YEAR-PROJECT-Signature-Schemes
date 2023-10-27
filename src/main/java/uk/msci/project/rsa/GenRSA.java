package uk.msci.project.rsa;

public class GenRSA {

  /**
   * The size of the key to be generated.
   */
  private int keySize;

  /**
   * Constructs a {@code KeyGenerator2} object with a specified key size.
   *
   * @param size The desired bit length of the RSA keys.
   * @throws IllegalArgumentException if the specified key size is invalid.
   */
  public GenRSA(int size) throws IllegalArgumentException {
    if (size >= 1024 && size <= 7680) {
      this.keySize = size;
    } else {
      throw new IllegalArgumentException(
          "Key size cannot be smaller than " + 1024 + "bits or larger than" + 7680
              + "bits");
    }
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
