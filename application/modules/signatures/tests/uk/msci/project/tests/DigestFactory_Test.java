package uk.msci.project.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.reflect.Field;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.msci.project.rsa.ANSI_X9_31_RDSA;
import uk.msci.project.rsa.DigestFactory;
import uk.msci.project.rsa.DigestType;
import uk.msci.project.rsa.GenRSA;
import uk.msci.project.rsa.RSASSA_PKCS1_v1_5;
import uk.msci.project.rsa.SigScheme;
import uk.msci.project.rsa.exceptions.InvalidDigestException;
import uk.msci.project.rsa.exceptions.InvalidSignatureTypeException;


public class DigestFactory_Test {

  private RSASSA_PKCS1_v1_5 rsassa_pkcs1_v1_5;


  @BeforeEach
  public void setup() {
    rsassa_pkcs1_v1_5 = new RSASSA_PKCS1_v1_5(
        new GenRSA(2, new int[]{512, 512}).generateKeyPair().getPrivateKey());

  }


  @Test
  public void testEnumValues() {
    // Test that all enum values are present
    DigestType[] types = DigestType.values();
    assertEquals(2, types.length);
    assertArrayEquals(
        new DigestType[]{DigestType.SHA_256, DigestType.SHA_512, DigestType.SHAKE_128,
            DigestType.SHAKE_256, DigestType.MGF_1_SHA_256, DigestType.MGF_1_SHA_512}, types);
  }

  @Test
  public void testGetDigestName() {
    // Test getSchemeName method
    assertEquals("SHA_256", DigestType.SHA_256.getDigestName());
    assertEquals("SHA_512", DigestType.SHA_512.getDigestName());
    assertEquals("SHAKE_128", DigestType.SHAKE_128.getDigestName());
    assertEquals("SHAKE_256", DigestType.SHAKE_256.getDigestName());
    assertEquals("MGF_1_SHA_256", DigestType.MGF_1_SHA_256.getDigestName());
    assertEquals("MGF_1_SHA_512", DigestType.MGF_1_SHA_512.getDigestName());
  }

  @Test
  public void testToString() {
    // Test toString method
    assertEquals("SHA_256", DigestType.SHA_256.toString());
    assertEquals("SHA_512", DigestType.SHA_512.toString());
    assertEquals("SHAKE_128", DigestType.SHAKE_128.toString());
    assertEquals("SHAKE_256", DigestType.SHAKE_256.toString());
    assertEquals("MGF_1_SHA_256", DigestType.MGF_1_SHA_256.toString());
    assertEquals("MGF_1_SHA_512", DigestType.MGF_1_SHA_512.toString());
  }

  @Test
  public void testSetDigestTypeSHA_256()
      throws NoSuchAlgorithmException, InvalidDigestException, NoSuchFieldException, IllegalAccessException, NoSuchProviderException {
    rsassa_pkcs1_v1_5.setDigest(DigestType.SHA_256);
    Field md = SigScheme.class.getDeclaredField("md");
    md.setAccessible(true);
    MessageDigest mdVal = (MessageDigest) md.get(rsassa_pkcs1_v1_5);
    assertEquals("SHA-256", mdVal.getAlgorithm());

    Field hashID = SigScheme.class.getDeclaredField("hashID");
    hashID.setAccessible(true);
    byte[] hashIDval = (byte[]) hashID.get(rsassa_pkcs1_v1_5);
    assertArrayEquals(hashIDval,
        new byte[]{(byte) 0x30, (byte) 0x31, (byte) 0x30, (byte) 0x0d, (byte) 0x06,
            (byte) 0x09, (byte) 0x60, (byte) 0x86, (byte) 0x48, (byte) 0x01,
            (byte) 0x65, (byte) 0x03, (byte) 0x04, (byte) 0x02, (byte) 0x01,
            (byte) 0x05, (byte) 0x00, (byte) 0x04, (byte) 0x20});

    ANSI_X9_31_RDSA ansi_x9_31_rdsa = new ANSI_X9_31_RDSA(
        new GenRSA(2, new int[]{512, 512}).generateKeyPair().getPrivateKey());
    hashIDval = (byte[]) hashID.get(ansi_x9_31_rdsa);
    assertArrayEquals(hashIDval,
        new byte[]{(byte) 0x34, (byte) 0xCC});
  }

  @Test
  public void testSetDigestTypeSHA_512()
      throws NoSuchAlgorithmException, InvalidDigestException, NoSuchFieldException, IllegalAccessException, NoSuchProviderException {
    rsassa_pkcs1_v1_5.setDigest(DigestType.SHA_512);
    Field md = SigScheme.class.getDeclaredField("md");
    md.setAccessible(true);
    MessageDigest mdVal = (MessageDigest) md.get(rsassa_pkcs1_v1_5);
    assertEquals("SHA-512", mdVal.getAlgorithm());

    Field hashID = SigScheme.class.getDeclaredField("hashID");
    hashID.setAccessible(true);
    byte[] hashIDval = (byte[]) hashID.get(rsassa_pkcs1_v1_5);
    assertArrayEquals(hashIDval, new byte[]{
        (byte) 0x30, (byte) 0x51, (byte) 0x30, (byte) 0x0D,
        (byte) 0x06, (byte) 0x09, (byte) 0x60, (byte) 0x86,
        (byte) 0x48, (byte) 0x01, (byte) 0x65, (byte) 0x03,
        (byte) 0x04, (byte) 0x02, (byte) 0x03, (byte) 0x05,
        (byte) 0x00, (byte) 0x04, (byte) 0x40});

    ANSI_X9_31_RDSA ansi_x9_31_rdsa = new ANSI_X9_31_RDSA(
        new GenRSA(2, new int[]{512, 512}).generateKeyPair().getPrivateKey());
    ansi_x9_31_rdsa.setDigest(DigestType.SHA_512);
    hashIDval = (byte[]) hashID.get(ansi_x9_31_rdsa);
    assertArrayEquals(hashIDval,
        new byte[]{(byte) 0x35, (byte) 0xCC});
  }

  @Test
  public void testSetDigestTypeSHAKE_128()
      throws NoSuchAlgorithmException, InvalidDigestException, NoSuchFieldException, IllegalAccessException, NoSuchProviderException {
    rsassa_pkcs1_v1_5.setDigest(DigestType.SHAKE_128);
    Field md = SigScheme.class.getDeclaredField("md");
    md.setAccessible(true);
    MessageDigest mdVal = (MessageDigest) md.get(rsassa_pkcs1_v1_5);
    assertEquals("SHAKE128", mdVal.getAlgorithm());

    Field hashID = SigScheme.class.getDeclaredField("hashID");
    hashID.setAccessible(true);
    byte[] hashIDval = (byte[]) hashID.get(rsassa_pkcs1_v1_5);
    assertArrayEquals(hashIDval, new byte[]{
        (byte) 0x30, (byte) 0x31, (byte) 0x30, (byte) 0x0D,
        (byte) 0x06, (byte) 0x09, (byte) 0x60, (byte) 0x86,
        (byte) 0x48, (byte) 0x01, (byte) 0x65, (byte) 0x03,
        (byte) 0x04, (byte) 0x02, (byte) 0x0B, (byte) 0x04,
        (byte) 0x20});

    ANSI_X9_31_RDSA ansi_x9_31_rdsa = new ANSI_X9_31_RDSA(
        new GenRSA(2, new int[]{512, 512}).generateKeyPair().getPrivateKey());
    ansi_x9_31_rdsa.setDigest(DigestType.SHAKE_128);
    hashIDval = (byte[]) hashID.get(ansi_x9_31_rdsa);
    assertArrayEquals(hashIDval,
        new byte[]{(byte) 0x3D, (byte) 0xCC});
  }

  @Test
  public void testSetDigestTypeSHAKE_256()
      throws NoSuchAlgorithmException, InvalidDigestException, NoSuchFieldException, IllegalAccessException, NoSuchProviderException {
    rsassa_pkcs1_v1_5.setDigest(DigestType.SHAKE_256);
    Field md = SigScheme.class.getDeclaredField("md");
    md.setAccessible(true);
    MessageDigest mdVal = (MessageDigest) md.get(rsassa_pkcs1_v1_5);
    assertEquals("SHAKE256", mdVal.getAlgorithm());

    Field hashID = SigScheme.class.getDeclaredField("hashID");
    hashID.setAccessible(true);
    byte[] hashIDval = (byte[]) hashID.get(rsassa_pkcs1_v1_5);
    assertArrayEquals(hashIDval, new byte[]{
        (byte) 0x30, (byte) 0x51, (byte) 0x30, (byte) 0x0D,
        (byte) 0x06, (byte) 0x09, (byte) 0x60, (byte) 0x86,
        (byte) 0x48, (byte) 0x01, (byte) 0x65, (byte) 0x03,
        (byte) 0x04, (byte) 0x02, (byte) 0x0C, (byte) 0x04,
        (byte) 0x40});

    ANSI_X9_31_RDSA ansi_x9_31_rdsa = new ANSI_X9_31_RDSA(
        new GenRSA(2, new int[]{512, 512}).generateKeyPair().getPrivateKey());
    ansi_x9_31_rdsa.setDigest(DigestType.SHAKE_256);
    hashIDval = (byte[]) hashID.get(ansi_x9_31_rdsa);
    assertArrayEquals(hashIDval,
        new byte[]{(byte) 0x3D, (byte) 0xCC});
  }

  @Test
  public void testSetDigestTypeMGF_1_SHA_256()
      throws NoSuchAlgorithmException, InvalidDigestException, NoSuchFieldException, IllegalAccessException, NoSuchProviderException {
    rsassa_pkcs1_v1_5.setDigest(DigestType.MGF_1_SHA_256);
    Field md = SigScheme.class.getDeclaredField("md");
    md.setAccessible(true);
    MessageDigest mdVal = (MessageDigest) md.get(rsassa_pkcs1_v1_5);
    assertEquals("SHA-256", mdVal.getAlgorithm());

    Field hashID = SigScheme.class.getDeclaredField("hashID");
    hashID.setAccessible(true);
    byte[] hashIDval = (byte[]) hashID.get(rsassa_pkcs1_v1_5);
    assertArrayEquals(hashIDval, new byte[]{
        (byte) 0x30, (byte) 0x18, (byte) 0x06, (byte) 0x08,
        (byte) 0x2A, (byte) 0x86, (byte) 0x48, (byte) 0x86,
        (byte) 0xF7, (byte) 0x0D, (byte) 0x01, (byte) 0x01,
        (byte) 0x08, (byte) 0x30, (byte) 0x0B, (byte) 0x06,
        (byte) 0x09, (byte) 0x60, (byte) 0x86, (byte) 0x48,
        (byte) 0x01, (byte) 0x65, (byte) 0x03, (byte) 0x04,
        (byte) 0x02, (byte) 0x01});

    ANSI_X9_31_RDSA ansi_x9_31_rdsa = new ANSI_X9_31_RDSA(
        new GenRSA(2, new int[]{512, 512}).generateKeyPair().getPrivateKey());
    ansi_x9_31_rdsa.setDigest(DigestType.MGF_1_SHA_256);
    hashIDval = (byte[]) hashID.get(ansi_x9_31_rdsa);
    assertArrayEquals(hashIDval,
        new byte[]{(byte) 0x34, (byte) 0xCC});
  }

  @Test
  public void testSetDigestTypeMGF_1_SHA_512()
      throws NoSuchAlgorithmException, InvalidDigestException, NoSuchFieldException, IllegalAccessException, NoSuchProviderException {
    rsassa_pkcs1_v1_5.setDigest(DigestType.MGF_1_SHA_512);
    Field md = SigScheme.class.getDeclaredField("md");
    md.setAccessible(true);
    MessageDigest mdVal = (MessageDigest) md.get(rsassa_pkcs1_v1_5);
    assertEquals("SHA-512", mdVal.getAlgorithm());

    Field hashID = SigScheme.class.getDeclaredField("hashID");
    hashID.setAccessible(true);
    byte[] hashIDval = (byte[]) hashID.get(rsassa_pkcs1_v1_5);
    assertArrayEquals(hashIDval, new byte[]{
        (byte) 0x30, (byte) 0x18,
        (byte) 0x06, (byte) 0x08, (byte) 0x2A, (byte) 0x86, (byte) 0x48, (byte) 0x86, (byte) 0xF7,
        (byte) 0x0D, (byte) 0x01, (byte) 0x01, (byte) 0x08,
        (byte) 0x30, (byte) 0x0B,
        (byte) 0x06, (byte) 0x09, (byte) 0x60, (byte) 0x86, (byte) 0x48, (byte) 0x01, (byte) 0x65,
        (byte) 0x03, (byte) 0x04, (byte) 0x02, (byte) 0x03
    });

    ANSI_X9_31_RDSA ansi_x9_31_rdsa = new ANSI_X9_31_RDSA(
        new GenRSA(2, new int[]{512, 512}).generateKeyPair().getPrivateKey());
    ansi_x9_31_rdsa.setDigest(DigestType.MGF_1_SHA_512);
    hashIDval = (byte[]) hashID.get(ansi_x9_31_rdsa);
    assertArrayEquals(hashIDval,
        new byte[]{(byte) 0x35, (byte) 0xCC});
  }


  @Test
  public void testGetDigestWithInvalidType() throws InvalidSignatureTypeException {
    assertThrows(NullPointerException.class,
        () -> DigestFactory.getMessageDigest(null),
        "Should thrown NullPointerException when digest type is invalid ");
  }


}

