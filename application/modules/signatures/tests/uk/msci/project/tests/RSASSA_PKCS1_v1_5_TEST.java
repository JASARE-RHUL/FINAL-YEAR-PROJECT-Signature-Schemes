package uk.msci.project.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.zip.DataFormatException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.msci.project.rsa.ByteArrayConverter;
import uk.msci.project.rsa.GenRSA;
import uk.msci.project.rsa.Key;
import uk.msci.project.rsa.KeyPair;
import uk.msci.project.rsa.RSASSA_PKCS1_v1_5;

public class RSASSA_PKCS1_v1_5_TEST {

  private RSASSA_PKCS1_v1_5 scheme;

  @BeforeEach
  // Before each test is run, clear any created key files.
  public void setup() {
    scheme = new RSASSA_PKCS1_v1_5(
        new GenRSA(2, new int[]{512, 512}).generateKeyPair().getPrivateKey());
  }

  @Test
  void testencodeMessage_InitialZero()
      throws DataFormatException, NoSuchMethodException, InvocationTargetException, IllegalAccessException {
    byte[] message = "test message 1".getBytes();
    Method encodeMethod = RSASSA_PKCS1_v1_5.class.getDeclaredMethod("encodeMessage",
        byte[].class);
    encodeMethod.setAccessible(true);
    byte[] encodedMessage = (byte[]) encodeMethod.invoke(scheme, (Object) message);

    assertEquals(0x00, encodedMessage[0], "The first byte of the encoded message should be 0x00");

  }

  @Test
  void testencodeMessage_BlockType()
      throws DataFormatException, NoSuchMethodException, InvocationTargetException, IllegalAccessException {
    byte[] message = "test message 2".getBytes();
    Method encodeMethod = RSASSA_PKCS1_v1_5.class.getDeclaredMethod("encodeMessage",
        byte[].class);
    encodeMethod.setAccessible(true);
    byte[] encodedMessage = (byte[]) encodeMethod.invoke(scheme, (Object) message);

    assertEquals(0x01, encodedMessage[1], "The block type byte should be 0x01");
  }

//  @Test
//  public void testencodeMessage_PaddingString()
//      throws DataFormatException, NoSuchAlgorithmException {
//    byte[] message = "test message 3".getBytes();
//    byte[] encodedMessage = scheme.encodeMessage(message);
//    MessageDigest md = MessageDigest.getInstance("SHA-256");
//    byte[] mHash = md.digest(message);
//
//    for (int i = 2; i < encodedMessage.length - mHash.length - 1; i++) {
//      assertEquals((byte) 0xFF, encodedMessage[i],
//          "Padding byte at index " + i + " should be 0xFF");
//    }
//  }
//
//  @Test
//  public void testencodeMessage_Separator()
//      throws DataFormatException, NoSuchAlgorithmException {
//    byte[] message = "test message 4".getBytes();
//    byte[] encodedMessage = scheme.encodeMessage(message);
//    MessageDigest md = MessageDigest.getInstance("SHA-256");
//    byte[] mHash = md.digest(message);
//    int separatorIndex = encodedMessage.length - mHash.length - 1;
//
//    assertEquals(0x00, encodedMessage[separatorIndex],
//        "The byte preceding the message should be 0x00");
//}
//
//  @Test
//  public void testencodeMessage_MessagePlacement()
//      throws DataFormatException, NoSuchAlgorithmException {
//    byte[] message = "test message 4".getBytes();
//    byte[] encodedMessage = scheme.encodeMessage(message);
//    MessageDigest md = MessageDigest.getInstance("SHA-256");
//    byte[] mHash = md.digest(message);
//    byte[] messageInEM = Arrays.copyOfRange(encodedMessage, encodedMessage.length - mHash.length,
//        encodedMessage.length);
//
//    assertArrayEquals(mHash, messageInEM,
//        "The message should be correctly placed at the end of the encoded message");
//  }
//
//  @Test
//  public void testencodeMessage_HashIncorporation()
//      throws DataFormatException, NoSuchAlgorithmException {
//    byte[] message = "Test message 5".getBytes();
//    MessageDigest md = MessageDigest.getInstance("SHA-256");
//
//    byte[] encodedMessage = scheme.encodeMessage(message);
//    byte[] mHash = md.digest(message);
//
//    // Extract the hash part from the encoded message
//    byte[] hashFromEncodedMessage = Arrays.copyOfRange(encodedMessage,
//        encodedMessage.length - mHash.length, encodedMessage.length);
//
//    assertArrayEquals(mHash, hashFromEncodedMessage,
//        "The hash in the encoded message should match the actual message hash");
//  }

  @Test
  public void testencodeMessage_PaddingString()
      throws DataFormatException, NoSuchAlgorithmException, InvocationTargetException, IllegalAccessException, NoSuchMethodException {
    byte[] message = "test message 7".getBytes();
    Method encodeMethod = RSASSA_PKCS1_v1_5.class.getDeclaredMethod("encodeMessage",
        byte[].class);
    encodeMethod.setAccessible(true);
    byte[] encodedMessage = (byte[]) encodeMethod.invoke(scheme, (Object) message);
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    byte[] mHash = md.digest(message);
    byte[] digestInfo = scheme.createDigestInfo(mHash);
    int tLen = digestInfo.length;

    for (int i = 2; i < encodedMessage.length - tLen - 1; i++) {
      assertEquals((byte) 0xFF, encodedMessage[i],
          "Padding byte at index " + i + " should be 0xFF");
    }
  }

  @Test
  public void testencodeMessage_Separator()
      throws DataFormatException, NoSuchAlgorithmException, NoSuchMethodException, InvocationTargetException, IllegalAccessException {
    byte[] message = "test message 8".getBytes();
    Method encodeMethod = RSASSA_PKCS1_v1_5.class.getDeclaredMethod("encodeMessage",
        byte[].class);
    encodeMethod.setAccessible(true);
    byte[] encodedMessage = (byte[]) encodeMethod.invoke(scheme, (Object) message);
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    byte[] mHash = md.digest(message);
    byte[] digestInfo = scheme.createDigestInfo(mHash);
    int tLen = digestInfo.length;
    int separatorIndex = encodedMessage.length - tLen - 1;

    assertEquals(0x00, encodedMessage[separatorIndex],
        "The byte preceding the message should be 0x00");
  }

  @Test
  public void testencodeMessage_MessagePlacement()
      throws DataFormatException, NoSuchAlgorithmException, InvocationTargetException, IllegalAccessException, NoSuchMethodException {
    byte[] message = "test message 9".getBytes();
    Method encodeMethod = RSASSA_PKCS1_v1_5.class.getDeclaredMethod("encodeMessage",
        byte[].class);
    encodeMethod.setAccessible(true);
    byte[] encodedMessage = (byte[]) encodeMethod.invoke(scheme, (Object) message);
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    byte[] mHash = md.digest(message);
    byte[] digestInfo = scheme.createDigestInfo(mHash);
    int tLen = digestInfo.length;
    byte[] messageInEM = Arrays.copyOfRange(encodedMessage, encodedMessage.length - tLen,
        encodedMessage.length);

    assertArrayEquals(digestInfo, messageInEM,
        "The message should be correctly placed at the end of the encoded message");
  }

  @Test
  public void testencodeMessage_HashIncorporation()
      throws DataFormatException, NoSuchAlgorithmException, InvocationTargetException, IllegalAccessException, NoSuchMethodException {
    byte[] message = "Test message 10".getBytes();
    MessageDigest md = MessageDigest.getInstance("SHA-256");

    Method encodeMethod = RSASSA_PKCS1_v1_5.class.getDeclaredMethod("encodeMessage",
        byte[].class);
    encodeMethod.setAccessible(true);
    byte[] encodedMessage = (byte[]) encodeMethod.invoke(scheme, (Object) message);
    byte[] mHash = md.digest(message);
    byte[] digestInfo = scheme.createDigestInfo(mHash);
    int tLen = digestInfo.length;

    // Extract the hash part from the encoded message
    byte[] hashFromEncodedMessage = Arrays.copyOfRange(encodedMessage,
        encodedMessage.length - tLen, encodedMessage.length);

    assertArrayEquals(digestInfo, hashFromEncodedMessage,
        "The hash in the encoded message should match the actual message hash");
  }

  @Test
  public void testOS2IPWithEmptyArray()
      throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
    byte[] emptyArray = new byte[0];

    Method OS2IPmethod = RSASSA_PKCS1_v1_5.class.getMethod("OS2IP", byte[].class);
    OS2IPmethod.setAccessible(true);
    BigInteger result = (BigInteger) OS2IPmethod.invoke(scheme, (Object) emptyArray);
    assertEquals(BigInteger.ZERO, result, "An empty byte array should convert to zero");
  }

  @Test
  public void testOS2IPWithNonEmptyArray()
      throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
    byte[] byteArray = {0x01, 0x02, 0x03, 0x04}; // Example byte array
    BigInteger expectedResult = new BigInteger(1, byteArray);
    Method OS2IPmethod = RSASSA_PKCS1_v1_5.class.getMethod("OS2IP", byte[].class);
    OS2IPmethod.setAccessible(true);
    BigInteger result = (BigInteger) OS2IPmethod.invoke(scheme, (Object) byteArray);

    assertEquals(expectedResult, result, "Byte array should correctly convert to BigInteger");
  }

  @Test
  public void testOS2IPWithLargeNumber()
      throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
    byte[] largeNumberArray = new byte[]{(byte) 0x8f, (byte) 0xad, (byte) 0xb8, (byte) 0xe0};
    BigInteger expectedResult = new BigInteger(1, largeNumberArray);
    Method OS2IPmethod = RSASSA_PKCS1_v1_5.class.getMethod("OS2IP", byte[].class);
    OS2IPmethod.setAccessible(true);
    BigInteger result = (BigInteger) OS2IPmethod.invoke(scheme, (Object) largeNumberArray);

    assertEquals(expectedResult, result,
        "Large number byte array should correctly convert to BigInteger");
  }

  @Test
  public void testOS2IPWithLeadingZeros()
      throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
    byte[] byteArrayWithZeros = {0x00, 0x00, 0x01, 0x02};
    BigInteger expectedResult = new BigInteger(1, byteArrayWithZeros);
    Method OS2IPmethod = RSASSA_PKCS1_v1_5.class.getMethod("OS2IP", byte[].class);
    OS2IPmethod.setAccessible(true);
    BigInteger result = (BigInteger) OS2IPmethod.invoke(scheme, (Object) byteArrayWithZeros);

    assertEquals(expectedResult, result,
        "Byte array with leading zeros should correctly convert to BigInteger");
  }

  @Test
  public void testRSASP1Consistency()
      throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
    BigInteger messageRepresentative = new BigInteger(
        "67543678998786"); // A fixed value for testing

    Method RSASP1method = RSASSA_PKCS1_v1_5.class.getMethod("RSASP1", BigInteger.class);
    RSASP1method.setAccessible(true);
    BigInteger firstSignature = (BigInteger) RSASP1method.invoke(scheme,
        (Object) messageRepresentative);
    BigInteger secondSignature = (BigInteger) RSASP1method.invoke(scheme,
        (Object) messageRepresentative);

    assertEquals(firstSignature, secondSignature,
        "Repeated executions should produce the same signature for fixed input");
  }

  @Test
  public void testI2OSPCorrectLength() {
    int emLen = 128; // Example length
    BigInteger number = new BigInteger("12345678901234567890");

    byte[] result = ByteArrayConverter.toFixedLengthByteArray(number, emLen);

    assertEquals(emLen, result.length, "The length of the resulting byte array should be " + emLen);
  }

  @Test
  public void testI2OSPLeadingZeroByteRemoval() {
    int emLen = 128; // Example length in bytes
    // Create a BigInteger with a known binary representation that includes a leading zero byte
    byte[] knownByteArray = new byte[emLen + 1];
    Arrays.fill(knownByteArray, (byte) 0);
    knownByteArray[1] = (byte) 0x01; // Set the second byte to 0x01 to simulate a leading zero in the BigInteger representation
    BigInteger number = new BigInteger(knownByteArray);

    byte[] result = ByteArrayConverter.toFixedLengthByteArray(number, emLen);

    assertEquals(emLen, result.length, "The length of the resulting byte array should be " + emLen);
    assertEquals((byte) 0x01, result[0],
        "The first byte should be 0x01, with leading zero byte removed");
    for (int i = 1; i < emLen; i++) {
      assertEquals((byte) 0x00, result[i], "The remaining bytes should be 0x00");
    }
  }

  @Test
  public void testI2OSPPaddingWithZeros() {
    int emLen = 128;
    BigInteger number = new BigInteger("1234567890");

    byte[] result = ByteArrayConverter.toFixedLengthByteArray(number, emLen);

    assertEquals(emLen, result.length, "The length of the resulting byte array should be " + emLen);
    // Verify that the padding (leading zeros) is present.
    for (int i = 0; i < emLen - result.length; i++) {
      assertEquals(0, result[i], "Byte at index " + i + " should be 0 due to padding");
    }
    // Verify the content of the BigInteger is at the end of the byte array.
    byte[] numberBytes = number.toByteArray();
    for (int i = 0; i < numberBytes.length; i++) {
      assertEquals(numberBytes[i], result[emLen - numberBytes.length + i],
          "Byte at index " + i + " should match the BigInteger byte value");
    }
  }

  @Test
  public void testI2OSPThrowsForIncorrectLength() {
    int emLen = 10; // Deliberately small length
    BigInteger number = new BigInteger("123456789012345678901234567890");
    assertThrows(IllegalArgumentException.class,
        () -> ByteArrayConverter.toFixedLengthByteArray(number, emLen),
        "Should throw byte array representation is longer than emLen ");
  }

  @Test
  void testSignAndVerifyRoundTrip() throws Exception {
    KeyPair keyPair = new GenRSA(2, new int[]{512, 512}).generateKeyPair();
    RSASSA_PKCS1_v1_5 schemeForSigning = new RSASSA_PKCS1_v1_5(keyPair.getPrivateKey());
    RSASSA_PKCS1_v1_5 schemeForVerifying = new RSASSA_PKCS1_v1_5(keyPair.getPublicKey());
    // Prepare a message
    byte[] message = "test message".getBytes();

    // Use reflection to invoke the private 'sign' method
    Method signMethod = RSASSA_PKCS1_v1_5.class.getMethod("sign", byte[].class);
    signMethod.setAccessible(true);

    // Invoke the 'sign' method and get the signature
    byte[] signature = (byte[]) signMethod.invoke(schemeForSigning, (Object) message);

    // Use reflection to invoke the private 'verify' method
    Method verifyMethod = RSASSA_PKCS1_v1_5.class.getMethod("verifyMessage",
        byte[].class, byte[].class);
    verifyMethod.setAccessible(true);

    // Invoke the 'verify' method and check if the signature is valid
    boolean isSignatureValid = (boolean) verifyMethod.invoke(schemeForVerifying, message,
        signature);

    // Assert that the signature is valid
    assertTrue(isSignatureValid, "The signature should be verified successfully.");
  }

  @Test
    // Test that verify correctly identifies an invalid signature.
  void testVerificationFailsForInvalidSignature() throws Exception {
    KeyPair keyPair = new GenRSA(2, new int[]{512, 512}).generateKeyPair();
    RSASSA_PKCS1_v1_5 schemeForVerifying = new RSASSA_PKCS1_v1_5(keyPair.getPublicKey());
    // Prepare a message and a random invalid signature
    byte[] message = "test message".getBytes();
    byte[] invalidSignature = new byte[128]; // Assuming RSA 1024-bit key
    new SecureRandom().nextBytes(invalidSignature); // Fill with random data

    // Use reflection to invoke the private 'verify' method
    Method verifyMethod = RSASSA_PKCS1_v1_5.class.getMethod("verifyMessage",
        byte[].class, byte[].class);
    verifyMethod.setAccessible(true);

    boolean isSignatureValid = (boolean) verifyMethod.invoke(schemeForVerifying, message,
        invalidSignature);
    assertFalse(isSignatureValid, "The invalid signature should not be verified.");
  }

  @Test
    // Test that altering a message after it's been signed results in a verification failure.
  void testVerificationFailsForAlteredMessage() throws Exception {
    KeyPair keyPair = new GenRSA(2, new int[]{512, 512}).generateKeyPair();
    RSASSA_PKCS1_v1_5 schemeForSigning = new RSASSA_PKCS1_v1_5(keyPair.getPrivateKey());
    RSASSA_PKCS1_v1_5 schemeForVerifying = new RSASSA_PKCS1_v1_5(keyPair.getPublicKey());
    // Sign a message
    byte[] originalMessage = "test message".getBytes();
    Method signMethod = RSASSA_PKCS1_v1_5.class.getMethod("sign", byte[].class);
    signMethod.setAccessible(true);
    byte[] signature = (byte[]) signMethod.invoke(schemeForSigning, (Object) originalMessage);

    // Alter the message
    byte[] alteredMessage = "test message altered".getBytes();

    // Use reflection to invoke the private 'verify' method
    Method verifyMethod = RSASSA_PKCS1_v1_5.class.getMethod("verifyMessage",
        byte[].class, byte[].class);
    verifyMethod.setAccessible(true);

    // Assert that the signature verification fails for the altered message
    boolean isSignatureValid = (boolean) verifyMethod.invoke(schemeForVerifying, alteredMessage,
        signature);
    assertFalse(isSignatureValid, "The signature should not be valid for an altered message.");
  }

  @Test
    // Test that altering a signature after it's been generated results in a verification failure.
  void testVerificationFailsForAlteredSignature() throws Exception {
    KeyPair keyPair = new GenRSA(2, new int[]{512, 512}).generateKeyPair();
    RSASSA_PKCS1_v1_5 schemeForSigning = new RSASSA_PKCS1_v1_5(keyPair.getPrivateKey());
    RSASSA_PKCS1_v1_5 schemeForVerifying = new RSASSA_PKCS1_v1_5(keyPair.getPublicKey());
    byte[] message = "test message".getBytes();
    Method signMethod = RSASSA_PKCS1_v1_5.class.getMethod("sign", byte[].class);
    signMethod.setAccessible(true);
    byte[] signature = (byte[]) signMethod.invoke(schemeForSigning, (Object) message);

    // Alter the signature (flip the last bit)
    signature[signature.length - 1] ^= 1;

    // Use reflection to invoke the private 'verify' method
    Method verifyMethod = RSASSA_PKCS1_v1_5.class.getMethod("verifyMessage",
        byte[].class, byte[].class);
    verifyMethod.setAccessible(true);

    // Assert that the signature verification fails for the altered signature
    boolean isSignatureValid = (boolean) verifyMethod.invoke(schemeForVerifying, message,
        signature);
    assertFalse(isSignatureValid, "The signature should not be valid for an altered signature.");
  }

  @Test
    // Test that signatures are only verified correctly with the matching public key, not with a different public key
  void testVerificationWithCorrectAndIncorrectKeys() throws Exception {
    KeyPair keyPair = new GenRSA(2, new int[]{512, 512}).generateKeyPair();
    RSASSA_PKCS1_v1_5 schemeForSigning1 = new RSASSA_PKCS1_v1_5(keyPair.getPrivateKey());
    RSASSA_PKCS1_v1_5 schemeForVerifying1 = new RSASSA_PKCS1_v1_5(keyPair.getPublicKey());
    // Sign a message
    byte[] message = "test message".getBytes();
    Method signMethod = RSASSA_PKCS1_v1_5.class.getMethod("sign", byte[].class);
    signMethod.setAccessible(true);
    byte[] signature = (byte[]) signMethod.invoke(schemeForSigning1, (Object) message);

    Method verifyMethod = RSASSA_PKCS1_v1_5.class.getMethod("verifyMessage",
        byte[].class, byte[].class);
    verifyMethod.setAccessible(true);
    // Use the correct public key for verification
    boolean isSignatureValidWithCorrectKey = (boolean) verifyMethod.invoke(schemeForVerifying1,
        message,
        signature);
    assertTrue(isSignatureValidWithCorrectKey,
        "The signature should be valid with the correct public key.");

    // Generate a new key pair, which will have a different public key
    Key incorrectPublicKey = new GenRSA(2, new int[]{512, 512}).generateKeyPair().getPublicKey();
    KeyPair keyPair2 = new GenRSA(2, new int[]{512, 512}).generateKeyPair();

    // Try to verify the signature with the incorrect public key
    RSASSA_PKCS1_v1_5 schemeWithIncorrectKey = new RSASSA_PKCS1_v1_5(keyPair2.getPublicKey());
    boolean isSignatureValidWithIncorrectKey = (boolean) verifyMethod.invoke(schemeWithIncorrectKey,
        message, signature);
    assertFalse(isSignatureValidWithIncorrectKey,
        "The signature should not be valid with an incorrect public key.");
  }


}







