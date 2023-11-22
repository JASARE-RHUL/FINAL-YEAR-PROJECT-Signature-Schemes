package uk.msci.project.test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.reflect.Field;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.msci.project.rsa.GenModel;
import uk.msci.project.rsa.GenRSA;
import uk.msci.project.rsa.ISO_IEC_9796_2_SCHEME_1;
import uk.msci.project.rsa.KeyPair;
import uk.msci.project.rsa.PrivateKey;
import uk.msci.project.rsa.PublicKey;
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
  }

  @Test
  public void testEnumValues() {
    // Test that all enum values are present
    SignatureType[] types = SignatureType.values();
    assertEquals(3, types.length);
    assertArrayEquals(new SignatureType[]{SignatureType.RSASSA_PKCS1_v1_5, SignatureType.ANSI_X9_31_RDSA, SignatureType.ISO_IEC_9796_2_SCHEME_1}, types);
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
  public void testSetSigTypePKCS()  {
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




}

