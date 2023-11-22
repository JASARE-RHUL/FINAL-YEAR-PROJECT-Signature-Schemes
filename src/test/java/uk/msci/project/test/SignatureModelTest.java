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



}

