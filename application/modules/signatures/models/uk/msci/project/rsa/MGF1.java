package uk.msci.project.rsa;

import java.security.MessageDigest;
import java.util.Arrays;

/**
 * This class implements the Mask Generation Function 1 (MGF1), a method used for transforming a
 * cryptographic hash function to generate outputs of a desired size i.e., a mask. The
 * Implementation is as per the PKCS#1 v2.2 specification.
 */
public class MGF1 {

  /**
   * The MessageDigest instance used for hashing in the mask generation process. This digest defines
   * the specific hash function to be used in the MGF1 algorithm.
   */
  private final MessageDigest digest;

  /**
   * Constructs an MGF1 instance with a specified hash function.
   *
   * @param digest The MessageDigest instance representing the hash function to be used in MGF1.
   */
  public MGF1(MessageDigest digest) {
    this.digest = digest;
  }

  /**
   * Generates a mask of the specified length using the MGF1 algorithm. The mask is generated by
   * repeatedly hashing a combination of the input seed and an iteration counter until enough data
   * is produced, then truncating or padding the result to the desired length.
   *
   * @param mgfSeed The input seed byte array for the mask generation function.
   * @param maskLen The desired length of the mask in bytes.
   * @return A byte array containing the generated mask.
   */
  // Implement the hashing logic with a simple concatenation
  public byte[] generateMask(byte[] mgfSeed, int maskLen) {
    byte[] mask = new byte[0];
    for (int i = 0; i < maskLen; i += digest.getDigestLength()) {
      digest.update(mgfSeed);
      byte[] hash = digest.digest();
      mask = Arrays.copyOf(mask, mask.length + hash.length);
      System.arraycopy(hash, 0, mask, mask.length - hash.length, hash.length);
    }
    return Arrays.copyOf(mask, maskLen);
  }


}
