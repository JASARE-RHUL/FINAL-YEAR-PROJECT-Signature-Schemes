package uk.msci.project.tests;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static uk.msci.project.tests.PublicKeyTest.deleteFilesWithSuffix;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import uk.msci.project.rsa.ANSI_X9_31_RDSA;
import uk.msci.project.rsa.ByteArrayConverter;
import uk.msci.project.rsa.GenModel;
import uk.msci.project.rsa.GenRSA;
import uk.msci.project.rsa.ISO_IEC_9796_2_SCHEME_1;
import uk.msci.project.rsa.KeyPair;
import uk.msci.project.rsa.PrivateKey;
import uk.msci.project.rsa.PublicKey;
import uk.msci.project.rsa.RSASSA_PKCS1_v1_5;
import uk.msci.project.rsa.SigScheme;
import uk.msci.project.rsa.SignatureFactory;
import uk.msci.project.rsa.SignatureModel;
import uk.msci.project.rsa.SignatureType;
import uk.msci.project.rsa.exceptions.InvalidDigestException;
import uk.msci.project.rsa.exceptions.InvalidSignatureTypeException;


public class SignatureModelTest {

  private SignatureModel signatureModel;

  private File createTestFileWithMessages(int numMessages) throws IOException {
    File file = new File(System.getProperty("user.dir"), "testMessages.txt");
    try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
      for (int i = 0; i < numMessages; i++) {
        writer.write("Message " + i);
        writer.newLine();
      }
    }
    return file;
  }


  private void prepareSignatureTestData() {
    List<byte[]> signatures = new ArrayList<>();
    // Populate signatures list with some dummy data
    signatures.add(new byte[]{1, 2, 3});
    signatures.add(new byte[]{4, 5, 6});
    signatureModel.getSignaturesFromBenchmark().addAll(signatures);
  }

  private void prepareNonRecoverableTestData() {
    List<byte[]> nonRecoverableMessages = new ArrayList<>();
    // Populate nonRecoverableMessages list with some dummy data
    nonRecoverableMessages.add(new byte[]{7, 8, 9});
    nonRecoverableMessages.add(new byte[]{}); // Example of an empty non-recoverable message
    signatureModel.getNonRecoverableMessages().addAll(nonRecoverableMessages);
  }


  @BeforeEach
  public void setup() {
    String fileNamePrefix = "testMessages";
    String fileExtension = "txt";
    deleteFilesWithSuffix(fileNamePrefix, fileExtension);
    deleteFilesWithSuffix("testNonRecoverableMessages", fileExtension);

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
        keyPair.getPrivateKey(), false);
    SigScheme resultPub = SignatureFactory.getSignatureScheme(SignatureType.RSASSA_PKCS1_v1_5,
        keyPair.getPrivateKey(), false);
    assertTrue(resultPriv instanceof RSASSA_PKCS1_v1_5);
    assertTrue(resultPub instanceof RSASSA_PKCS1_v1_5);
  }

  @Test
  public void testGetSignatureSchemeANSI_X9_31_RDSA() throws InvalidSignatureTypeException {
    KeyPair keyPair = new GenRSA(2, new int[]{512, 512}).generateKeyPair();
    SigScheme resultPriv = SignatureFactory.getSignatureScheme(SignatureType.ANSI_X9_31_RDSA,
        keyPair.getPrivateKey(), false);
    SigScheme resultPub = SignatureFactory.getSignatureScheme(SignatureType.ANSI_X9_31_RDSA,
        keyPair.getPrivateKey(), false);
    assertTrue(resultPriv instanceof ANSI_X9_31_RDSA);
    assertTrue(resultPub instanceof ANSI_X9_31_RDSA);
  }

  @Test
  public void testGetSignatureSchemeISO_IEC_9796_2_SCHEME_1() throws InvalidSignatureTypeException {
    KeyPair keyPair = new GenRSA(2, new int[]{512, 512}).generateKeyPair();
    SigScheme resultPriv = SignatureFactory.getSignatureScheme(
        SignatureType.ISO_IEC_9796_2_SCHEME_1,
        keyPair.getPrivateKey(), false);
    SigScheme resultPub = SignatureFactory.getSignatureScheme(SignatureType.ISO_IEC_9796_2_SCHEME_1,
        keyPair.getPrivateKey(), false);
    assertTrue(resultPriv instanceof ISO_IEC_9796_2_SCHEME_1);
    assertTrue(resultPub instanceof ISO_IEC_9796_2_SCHEME_1);
  }

  @Test
  public void testGetSignatureSchemeWithInvalidType() throws InvalidSignatureTypeException {
    KeyPair keyPair = new GenRSA(2, new int[]{512, 512}).generateKeyPair();
    assertThrows(NullPointerException.class,
        () -> SignatureFactory.getSignatureScheme(null, keyPair.getPublicKey(), false),
        "Should thrown NullPointerException when signature type is invalid ");
  }

  @Test
  void testInstantiateSignatureSchemeValidPKCS()
      throws IllegalAccessException, NoSuchFieldException, InvalidSignatureTypeException, NoSuchAlgorithmException, InvalidDigestException, NoSuchProviderException {
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
      throws IllegalAccessException, NoSuchFieldException, InvalidSignatureTypeException, NoSuchAlgorithmException, InvalidDigestException, NoSuchProviderException {
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
      throws IllegalAccessException, NoSuchFieldException, InvalidSignatureTypeException, NoSuchAlgorithmException, InvalidDigestException, NoSuchProviderException {
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

  @Test
  public void testBatchCreateSignatures() throws Exception {
    // Prepare test data and mock objects if needed
    File testFile = createTestFileWithMessages(10); // 10 messages for example

    // Execute the batchCreateSignatures method
    signatureModel.addPrivKeyToBatch(
        new GenRSA(2, new int[]{512, 512}).generateKeyPair().getPrivateKey().getKeyValue());
    signatureModel.setNumTrials(10);
    signatureModel.setSignatureType(SignatureType.ANSI_X9_31_RDSA);
    signatureModel.batchCreateSignatures(testFile, progress -> {
    });

    // Assertions for signatures and non-recoverable messages
    List<byte[]> signatures = signatureModel.getSignaturesFromBenchmark();
    List<byte[]> nonRecoverableMessages = signatureModel.getNonRecoverableMessages();
    assertEquals(10, signatures.size());
    assertEquals(10, nonRecoverableMessages.size());

    // Assertions for clockTimesPerTrial
    List<Long> timesPerTrial = signatureModel.getClockTimesPerTrial();
    assertEquals(10, timesPerTrial.size());

    for (Long time : timesPerTrial) {
      assertTrue(time > 0);
    }

  }


  @Test
  public void testExportSignatureBatch() throws IOException {
    // Prepare test data
    String testFileName = "testSignatures.txt";
    prepareSignatureTestData();

    // Execute the method to be tested
    signatureModel.exportSignatureBatch("testSignatures.txt");

    // Read the created file and assert its content
    File outputFile = new File(System.getProperty("user.dir"), testFileName);
    assertTrue(outputFile.exists());

    try (BufferedReader reader = new BufferedReader(new FileReader(outputFile))) {
      String line;
      int count = 0;
      while ((line = reader.readLine()) != null) {
        assertEquals(
            new BigInteger(1, signatureModel.getSignaturesFromBenchmark().get(count)).toString(),
            line);
        count++;
      }
      assertEquals(signatureModel.getSignaturesFromBenchmark().size(), count);
    }
  }

  @Test
  public void testExportNonRecoverableBatch() throws IOException {
    // Prepare test data
    String testFileName = "testNonRecoverableMessages.txt";
    prepareNonRecoverableTestData();

    // Execute the method to be tested
    signatureModel.exportNonRecoverableBatch(testFileName);

    // Read the created file and assert its content
    File outputFile = new File(System.getProperty("user.dir"), testFileName);
    assertTrue(outputFile.exists());

    try (BufferedReader reader = new BufferedReader(new FileReader(outputFile))) {
      String line;
      int count = 0;
      while ((line = reader.readLine()) != null) {
        byte[] nonRecoverableMessage = signatureModel.getNonRecoverableMessages().get(count);
        if (nonRecoverableMessage != null && nonRecoverableMessage.length > 0) {
          assertEquals("1 " + new String(nonRecoverableMessage), line);
        } else {
          assertEquals("0", line);
        }
        count++;
      }
      assertEquals(signatureModel.getNonRecoverableMessages().size(), count);
    }
  }


}

