package uk.msci.project.test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.reflect.Field;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.msci.project.rsa.ANSI_X9_31_RDSA;
import uk.msci.project.rsa.ByteArrayConverter;
import uk.msci.project.rsa.GenModel;
import uk.msci.project.rsa.GenRSA;
import uk.msci.project.rsa.ISO_IEC_9796_2_SCHEME_1;
import uk.msci.project.rsa.InvalidSignatureTypeException;
import uk.msci.project.rsa.KeyPair;
import uk.msci.project.rsa.PrivateKey;
import uk.msci.project.rsa.PublicKey;
import uk.msci.project.rsa.RSASSA_PKCS1_v1_5;
import uk.msci.project.rsa.SigScheme;
import uk.msci.project.rsa.SignatureFactory;
import uk.msci.project.rsa.SignatureModel;
import uk.msci.project.rsa.SignatureType;


public class SignatureModelTest {

  private SignatureModel signatureModel;


  @BeforeEach
  public void setup() {
    signatureModel = new SignatureModel();

  }

  @Test
  void testInitialization() {
    assertNotNull("SignatureModel should initialise an object", signatureModel);

  }

  @Test
  public void testSetPrivateKey() throws IllegalAccessException, NoSuchFieldException {
    KeyPair keyPair = new GenRSA(2, new int[]{512, 512}).generateKeyPair();
    signatureModel.setKey(keyPair.getPrivateKey());
    Field key = SignatureModel.class.getDeclaredField("key");
    key.setAccessible(true);
    PrivateKey keyVal = (PrivateKey) key.get(signatureModel);
    assertEquals(keyPair.getPrivateKey(), keyVal);
  }

  @Test
  public void testSetPublicKey() throws IllegalAccessException, NoSuchFieldException {
    KeyPair keyPair = new GenRSA(2, new int[]{512, 512}).generateKeyPair();
    signatureModel.setKey(keyPair.getPublicKey());
    Field key = SignatureModel.class.getDeclaredField("key");
    key.setAccessible(true);
    PublicKey keyVal = (PublicKey) key.get(signatureModel);
    assertEquals(keyPair.getPublicKey(), keyVal);
  }

  @Test
  public void testEnumValues() {
    // Test that all enum values are present
    SignatureType[] types = SignatureType.values();
    assertEquals(3, types.length);
    assertArrayEquals(
        new SignatureType[]{SignatureType.RSASSA_PKCS1_v1_5, SignatureType.ANSI_X9_31_RDSA,
            SignatureType.ISO_IEC_9796_2_SCHEME_1}, types);
  }

  @Test
  public void testGetSchemeName() {
    // Test getSchemeName method
    assertEquals("RSASSA_PKCS1_v1_5", SignatureType.RSASSA_PKCS1_v1_5.getSchemeName());
    assertEquals("ANSI_X9_31_RDSA", SignatureType.ANSI_X9_31_RDSA.getSchemeName());
    assertEquals("ISO_IEC_9796_2_SCHEME_1", SignatureType.ISO_IEC_9796_2_SCHEME_1.getSchemeName());
  }

  @Test
  public void testToString() {
    // Test toString method
    assertEquals("RSASSA_PKCS1_v1_5", SignatureType.RSASSA_PKCS1_v1_5.toString());
    assertEquals("ANSI_X9_31_RDSA", SignatureType.ANSI_X9_31_RDSA.toString());
    assertEquals("ISO_IEC_9796_2_SCHEME_1", SignatureType.ISO_IEC_9796_2_SCHEME_1.toString());
  }

  @Test
  public void testSetSigTypePKCS() {
    signatureModel.setSignatureType(SignatureType.RSASSA_PKCS1_v1_5);
    assertEquals(SignatureType.RSASSA_PKCS1_v1_5, signatureModel.getSignatureType());
  }

  @Test
  public void testSetSigTypeANSI() {
    signatureModel.setSignatureType(SignatureType.ANSI_X9_31_RDSA);
    assertEquals(SignatureType.ANSI_X9_31_RDSA, signatureModel.getSignatureType());
  }

  @Test
  public void testSetSigTypeISO() {
    signatureModel.setSignatureType(SignatureType.ISO_IEC_9796_2_SCHEME_1);
    assertEquals(SignatureType.ISO_IEC_9796_2_SCHEME_1, signatureModel.getSignatureType());
  }

  @Test
  public void testGetSignatureSchemeRSASSA_PKCS1_v1_5() throws InvalidSignatureTypeException {
    KeyPair keyPair = new GenRSA(2, new int[]{512, 512}).generateKeyPair();
    SigScheme resultPriv = SignatureFactory.getSignatureScheme(SignatureType.RSASSA_PKCS1_v1_5,
        keyPair.getPrivateKey());
    SigScheme resultPub = SignatureFactory.getSignatureScheme(SignatureType.RSASSA_PKCS1_v1_5,
        keyPair.getPrivateKey());
    assertTrue(resultPriv instanceof RSASSA_PKCS1_v1_5);
    assertTrue(resultPub instanceof RSASSA_PKCS1_v1_5);
  }

  @Test
  public void testGetSignatureSchemeANSI_X9_31_RDSA() throws InvalidSignatureTypeException {
    KeyPair keyPair = new GenRSA(2, new int[]{512, 512}).generateKeyPair();
    SigScheme resultPriv = SignatureFactory.getSignatureScheme(SignatureType.ANSI_X9_31_RDSA,
        keyPair.getPrivateKey());
    SigScheme resultPub = SignatureFactory.getSignatureScheme(SignatureType.ANSI_X9_31_RDSA,
        keyPair.getPrivateKey());
    assertTrue(resultPriv instanceof ANSI_X9_31_RDSA);
    assertTrue(resultPub instanceof ANSI_X9_31_RDSA);
  }

  @Test
  public void testGetSignatureSchemeISO_IEC_9796_2_SCHEME_1() throws InvalidSignatureTypeException {
    KeyPair keyPair = new GenRSA(2, new int[]{512, 512}).generateKeyPair();
    SigScheme resultPriv = SignatureFactory.getSignatureScheme(
        SignatureType.ISO_IEC_9796_2_SCHEME_1,
        keyPair.getPrivateKey());
    SigScheme resultPub = SignatureFactory.getSignatureScheme(SignatureType.ISO_IEC_9796_2_SCHEME_1,
        keyPair.getPrivateKey());
    assertTrue(resultPriv instanceof ISO_IEC_9796_2_SCHEME_1);
    assertTrue(resultPub instanceof ISO_IEC_9796_2_SCHEME_1);
  }

  @Test
  public void testGetSignatureSchemeWithInvalidType() throws InvalidSignatureTypeException {
    KeyPair keyPair = new GenRSA(2, new int[]{512, 512}).generateKeyPair();
    assertThrows(NullPointerException.class,
        () -> SignatureFactory.getSignatureScheme(null, keyPair.getPublicKey()),
        "Should thrown NullPointerException when signature type is invalid ");
  }

  @Test
  void testInstantiateSignatureSchemeValidPKCS()
      throws IllegalAccessException, NoSuchFieldException, InvalidSignatureTypeException {
    signatureModel.setSignatureType(SignatureType.RSASSA_PKCS1_v1_5);
    signatureModel.setKey(new GenRSA(2, new int[]{512, 512}).generateKeyPair().getPrivateKey());
    signatureModel.instantiateSignatureScheme();
    Field currentSignatureScheme = SignatureModel.class.getDeclaredField("currentSignatureScheme");
    currentSignatureScheme.setAccessible(true);
    SigScheme currentSignatureSchemeVal = (SigScheme) currentSignatureScheme.get(signatureModel);
    assertTrue(currentSignatureSchemeVal instanceof RSASSA_PKCS1_v1_5);

  }

  @Test
  void testInstantiateSignatureSchemeValidANSI()
      throws IllegalAccessException, NoSuchFieldException, InvalidSignatureTypeException {
    signatureModel.setSignatureType(SignatureType.ANSI_X9_31_RDSA);
    signatureModel.setKey(new GenRSA(2, new int[]{512, 512}).generateKeyPair().getPrivateKey());
    signatureModel.instantiateSignatureScheme();
    Field currentSignatureScheme = SignatureModel.class.getDeclaredField("currentSignatureScheme");
    currentSignatureScheme.setAccessible(true);
    SigScheme currentSignatureSchemeVal = (SigScheme) currentSignatureScheme.get(signatureModel);
    assertTrue(currentSignatureSchemeVal instanceof ANSI_X9_31_RDSA);

  }

  @Test
  void testInstantiateSignatureSchemeValidISO()
      throws IllegalAccessException, NoSuchFieldException, InvalidSignatureTypeException {
    signatureModel.setSignatureType(SignatureType.ISO_IEC_9796_2_SCHEME_1);
    signatureModel.setKey(new GenRSA(2, new int[]{512, 512}).generateKeyPair().getPrivateKey());
    signatureModel.instantiateSignatureScheme();
    Field currentSignatureScheme = SignatureModel.class.getDeclaredField("currentSignatureScheme");
    currentSignatureScheme.setAccessible(true);
    SigScheme currentSignatureSchemeVal = (SigScheme) currentSignatureScheme.get(signatureModel);
    assertTrue(currentSignatureSchemeVal instanceof ISO_IEC_9796_2_SCHEME_1);

  }
  @Test
  void testInstantiateSignatureNullKey()
      throws IllegalAccessException, NoSuchFieldException, InvalidSignatureTypeException {
    signatureModel.setSignatureType(SignatureType.ISO_IEC_9796_2_SCHEME_1);
    assertThrows(IllegalStateException.class,
        () -> signatureModel.instantiateSignatureScheme(),
        "Both key and signature type need to be set before instantiating a signature scheme");

  }
  @Test
  void testInstantiateSignatureNullType()
      throws IllegalAccessException, NoSuchFieldException, InvalidSignatureTypeException {
    signatureModel.setKey(new GenRSA(2, new int[]{512, 512}).generateKeyPair().getPrivateKey());
    assertThrows(IllegalStateException.class,
        () -> signatureModel.instantiateSignatureScheme(),
        "Both key and signature type need to be set before instantiating a signature scheme");
  }
  @Test
  void testInstantiateSignatureNull()
      throws IllegalAccessException, NoSuchFieldException, InvalidSignatureTypeException {
    assertThrows(IllegalStateException.class,
        () -> signatureModel.instantiateSignatureScheme(),
        "Both key and signature type need to be set before instantiating a signature scheme");
  }


}

