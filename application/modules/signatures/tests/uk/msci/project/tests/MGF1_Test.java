package uk.msci.project.tests;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.msci.project.rsa.MGF1;
import uk.msci.project.rsa.SignatureModel;

public class MGF1_Test {

  private MGF1 mgf1;


  @BeforeEach
  public void setup() throws NoSuchAlgorithmException {
    mgf1 = new MGF1(MessageDigest.getInstance("SHA-256"));
  }

  @Test
  void testReturnLength() {
    assertEquals(256, mgf1.generateMask(new byte[0], 256).length);

  }

  @Test
  void testGenerateMaskEqualSeeds() throws NoSuchAlgorithmException {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    MGF1 mgf1 = new MGF1(md);
    byte[] seed1 = new byte[]{1, 2, 3};
    byte[] seed2 = new byte[]{1, 2, 3};
    int maskLen = 20;
    byte[] mask1 = mgf1.generateMask(seed1, maskLen);
    byte[] mask2 = mgf1.generateMask(seed2, maskLen);
    assertTrue(Arrays.equals(mask1, mask2),
        "Masks generated from with the same seed should be equal.");
  }

  @Test
  void testGenerateMaskVaryingSeed() throws NoSuchAlgorithmException {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    MGF1 mgf1 = new MGF1(md);
    byte[] seed1 = new byte[]{1, 2, 3};
    byte[] seed2 = new byte[]{4, 5, 6};
    int maskLen = 20;
    byte[] mask1 = mgf1.generateMask(seed1, maskLen);
    byte[] mask2 = mgf1.generateMask(seed2, maskLen);
    assertFalse(Arrays.equals(mask1, mask2), "Masks generated from different seeds should differ.");
  }

  @Test
  void testGenerateMaskWithZeroLengthSeed() throws NoSuchAlgorithmException {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    MGF1 mgf1 = new MGF1(md);
    byte[] seed = new byte[0]; // Zero-length seed
    int maskLen = 20;

    byte[] mask = mgf1.generateMask(seed, maskLen);
    // Mask should not be null even with zero-length seed.
    Assertions.assertNotNull(mask);
    Assertions.assertEquals(maskLen, mask.length,
        "Mask length should be correct with zero-length seed.");
  }


}
