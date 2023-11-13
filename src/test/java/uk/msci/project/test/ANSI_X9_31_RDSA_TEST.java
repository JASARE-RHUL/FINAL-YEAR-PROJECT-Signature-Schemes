package uk.msci.project.test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
import uk.msci.project.rsa.ANSI_X9_31_RDSA;
import uk.msci.project.rsa.ByteArrayConverter;
import uk.msci.project.rsa.GenRSA;
import uk.msci.project.rsa.Key;
import uk.msci.project.rsa.KeyPair;
import uk.msci.project.rsa.ANSI_X9_31_RDSA;

public class ANSI_X9_31_RDSA_TEST {

  private ANSI_X9_31_RDSA scheme;

  @BeforeEach
  // Before each test is run, clear any created key files.
  public void setup() {
    scheme = new ANSI_X9_31_RDSA(
        new GenRSA(2, new int[]{512, 512}).generateKeyPair().getPrivateKey());
  }

  @Test
  void testANSI_X9_31_RDSA_initialBytePadding()
      throws DataFormatException, NoSuchMethodException, InvocationTargetException, IllegalAccessException {
    byte[] message = "test message 1".getBytes();
    Method encodeMethod = ANSI_X9_31_RDSA.class.getDeclaredMethod("encodeMessage",
        byte[].class);
    encodeMethod.setAccessible(true);
    byte[] encodedMessage = (byte[]) encodeMethod.invoke(scheme, (Object) message);

    assertEquals(0x6B, encodedMessage[0], "The first byte of the encoded message should be 0x6B");

  }

  @Test
  void testANSI_X9_31_RDSA_finalBytePadding()
      throws DataFormatException, NoSuchMethodException, InvocationTargetException, IllegalAccessException, NoSuchAlgorithmException {
    byte[] message = "test message 1".getBytes();
    Method encodeMethod = ANSI_X9_31_RDSA.class.getDeclaredMethod("encodeMessage",
        byte[].class);
    encodeMethod.setAccessible(true);
    byte[] encodedMessage = (byte[]) encodeMethod.invoke(scheme, (Object) message);
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    byte[] mHash = md.digest(message);
    byte[] digestInfo = scheme.createDigestInfo(mHash);
    int tLen = digestInfo.length;

    assertEquals((byte) 0xBA, encodedMessage[encodedMessage.length - tLen - 1], "The final byte of the encoded message should be 0xBA");

  }


  @Test
  void testencodeMessage_PaddingString()
      throws DataFormatException, NoSuchAlgorithmException, InvocationTargetException, IllegalAccessException, NoSuchMethodException {
    byte[] message = "test message 7".getBytes();
    Method encodeMethod = ANSI_X9_31_RDSA.class.getDeclaredMethod("encodeMessage",
        byte[].class);
    encodeMethod.setAccessible(true);
    byte[] encodedMessage = (byte[]) encodeMethod.invoke(scheme, (Object) message);
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    byte[] mHash = md.digest(message);
    byte[] digestInfo = scheme.createDigestInfo(mHash);
    int tLen = digestInfo.length;

    for (int i = 1; i < encodedMessage.length - tLen - 1; i++) {
      assertEquals((byte) 0xBB, encodedMessage[i],
          "Padding byte at index " + i + " should be 0xBB");
    }
  }



  @Test
  public void testencodeMessage_MessagePlacement()
      throws DataFormatException, NoSuchAlgorithmException, InvocationTargetException, IllegalAccessException, NoSuchMethodException {
    byte[] message = "test message 9".getBytes();
    Method encodeMethod = ANSI_X9_31_RDSA.class.getDeclaredMethod("encodeMessage",
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

    Method encodeMethod = ANSI_X9_31_RDSA.class.getDeclaredMethod("encodeMessage",
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
  void testSignAndVerifyRoundTrip() throws Exception {
    KeyPair keyPair = new GenRSA(2, new int[]{512, 512}).generateKeyPair();
    ANSI_X9_31_RDSA schemeForSigning = new ANSI_X9_31_RDSA(keyPair.getPrivateKey());
    ANSI_X9_31_RDSA schemeForVerifying = new ANSI_X9_31_RDSA(keyPair.getPublicKey());
    // Prepare a message
    byte[] message = "test message".getBytes();

    // Use reflection to invoke the private 'sign' method
    Method signMethod = ANSI_X9_31_RDSA.class.getMethod("sign", byte[].class);
    signMethod.setAccessible(true);

    // Invoke the 'sign' method and get the signature
    byte[] signature = (byte[]) signMethod.invoke(schemeForSigning, (Object) message);

    // Use reflection to invoke the private 'verify' method
    Method verifyMethod = ANSI_X9_31_RDSA.class.getMethod("verifyMessage",
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
    ANSI_X9_31_RDSA schemeForVerifying = new ANSI_X9_31_RDSA(keyPair.getPublicKey());
    // Prepare a message and a random invalid signature
    byte[] message = "test message".getBytes();
    byte[] invalidSignature = new byte[128]; // Assuming RSA 1024-bit key
    new SecureRandom().nextBytes(invalidSignature); // Fill with random data

    // Use reflection to invoke the private 'verify' method
    Method verifyMethod = ANSI_X9_31_RDSA.class.getMethod("verifyMessage",
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
    ANSI_X9_31_RDSA schemeForSigning = new ANSI_X9_31_RDSA(keyPair.getPrivateKey());
    ANSI_X9_31_RDSA schemeForVerifying = new ANSI_X9_31_RDSA(keyPair.getPublicKey());
    // Sign a message
    byte[] originalMessage = "test message".getBytes();
    Method signMethod = ANSI_X9_31_RDSA.class.getMethod("sign", byte[].class);
    signMethod.setAccessible(true);
    byte[] signature = (byte[]) signMethod.invoke(schemeForSigning, (Object) originalMessage);

    // Alter the message
    byte[] alteredMessage = "test message altered".getBytes();

    // Use reflection to invoke the private 'verify' method
    Method verifyMethod = ANSI_X9_31_RDSA.class.getMethod("verifyMessage",
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
    ANSI_X9_31_RDSA schemeForSigning = new ANSI_X9_31_RDSA(keyPair.getPrivateKey());
    ANSI_X9_31_RDSA schemeForVerifying = new ANSI_X9_31_RDSA(keyPair.getPublicKey());
    byte[] message = "test message".getBytes();
    Method signMethod = ANSI_X9_31_RDSA.class.getMethod("sign", byte[].class);
    signMethod.setAccessible(true);
    byte[] signature = (byte[]) signMethod.invoke(schemeForSigning, (Object) message);

    // Alter the signature (flip the last bit)
    signature[signature.length - 1] ^= 1;

    // Use reflection to invoke the private 'verify' method
    Method verifyMethod = ANSI_X9_31_RDSA.class.getMethod("verifyMessage",
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
    ANSI_X9_31_RDSA schemeForSigning1 = new ANSI_X9_31_RDSA(keyPair.getPrivateKey());
    ANSI_X9_31_RDSA schemeForVerifying1 = new ANSI_X9_31_RDSA(keyPair.getPublicKey());
    // Sign a message
    byte[] message = "test message".getBytes();
    Method signMethod = ANSI_X9_31_RDSA.class.getMethod("sign", byte[].class);
    signMethod.setAccessible(true);
    byte[] signature = (byte[]) signMethod.invoke(schemeForSigning1, (Object) message);

    Method verifyMethod = ANSI_X9_31_RDSA.class.getMethod("verifyMessage",
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
    ANSI_X9_31_RDSA schemeWithIncorrectKey = new ANSI_X9_31_RDSA(keyPair2.getPublicKey());
    boolean isSignatureValidWithIncorrectKey = (boolean) verifyMethod.invoke(schemeWithIncorrectKey,
        message, signature);
    assertFalse(isSignatureValidWithIncorrectKey,
        "The signature should not be valid with an incorrect public key.");
  }


}







