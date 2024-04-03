package uk.msci.project.tests;

import static org.junit.Assert.assertFalse;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.stream.Stream;
import java.util.zip.DataFormatException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import uk.msci.project.rsa.GenRSA;
import uk.msci.project.rsa.ISO_IEC_9796_2_SCHEME_1;
import uk.msci.project.rsa.Key;
import uk.msci.project.rsa.KeyPair;
import uk.msci.project.rsa.MGF1;
import uk.msci.project.rsa.RSASSA_PKCS1_v1_5;
import uk.msci.project.rsa.SigScheme;

public class ISO_IEC_9796_2_SCHEME_1_TEST {

  private ISO_IEC_9796_2_SCHEME_1 scheme;

  private static Stream<Object[]> provableOrStandardParameters() {
    return Stream.of(
        // standard parameters
        new Object[]{new GenRSA(2, new int[]{512, 512}).generateKeyPair().getPrivateKey(), null},
        // provably secure parameters
        new Object[]{new GenRSA(2, new int[]{512, 512}).generateKeyPair().getPrivateKey(), true}
    );
  }

  @ParameterizedTest
  @MethodSource("provableOrStandardParameters")
  void testInitialBytePadding(Key key, Boolean isProvablySecureParams) throws Exception {
    if (isProvablySecureParams == null) {
      scheme = new ISO_IEC_9796_2_SCHEME_1(key);
    } else {
      scheme = new ISO_IEC_9796_2_SCHEME_1(key, isProvablySecureParams);

      Field emLen = SigScheme.class.getDeclaredField("emLen");
      emLen.setAccessible(true);
      int emLenVal = (int) emLen.get(scheme);
      Field hashSize = ISO_IEC_9796_2_SCHEME_1.class.getDeclaredField("hashSize");
      hashSize.setAccessible(true);
      int hashSizeVal = (int) hashSize.get(scheme);
      assertEquals((emLenVal + 1) / 2, hashSizeVal);
    }
    byte[] message = (
        "test message test message test message test message test message test message "
            + "test message test message test message test message test message test message test messa"
            + "ge test message test message test message test message test message test message tes"
            + "t message test message test message test message 1").getBytes();
    byte[] message2 = "Test message".getBytes();
    Method encodeMethod = ISO_IEC_9796_2_SCHEME_1.class.getDeclaredMethod("encodeMessage",
        byte[].class);
    encodeMethod.setAccessible(true);
    byte[] encodedMessage = (byte[]) encodeMethod.invoke(scheme, (Object) message);
    assertEquals((0x60 | (0x0A & 0x0F)), encodedMessage[0],
        "The first non zero byte of the encoded message should match 0X6A for suffcicently long messages with a recoverable component.");

    byte[] encodedMessage2 = (byte[]) encodeMethod.invoke(scheme, (Object) message2);
    assertEquals((0x40 | (0x0B & 0x0F)), encodedMessage2[0],
        "The first non zero byte of the encoded message should match 0x4A for shorter message that do not have a recoverable component");
  }

  @ParameterizedTest
  @MethodSource("provableOrStandardParameters")
  void testFinalBytePadding(Key key, Boolean isProvablySecureParams) throws Exception {
    if (isProvablySecureParams == null) {
      scheme = new ISO_IEC_9796_2_SCHEME_1(key);
    } else {
      scheme = new ISO_IEC_9796_2_SCHEME_1(key, isProvablySecureParams);

      Field emLen = SigScheme.class.getDeclaredField("emLen");
      emLen.setAccessible(true);
      int emLenVal = (int) emLen.get(scheme);
      Field hashSize = ISO_IEC_9796_2_SCHEME_1.class.getDeclaredField("hashSize");
      hashSize.setAccessible(true);
      int hashSizeVal = (int) hashSize.get(scheme);
      assertEquals((emLenVal + 1) / 2, hashSizeVal);
    }
    byte[] message = "test".getBytes();
    Method encodeMethod = ISO_IEC_9796_2_SCHEME_1.class.getDeclaredMethod("encodeMessage",
        byte[].class);
    encodeMethod.setAccessible(true);
    byte[] encodedMessage = (byte[]) encodeMethod.invoke(scheme, (Object) message);

    Field PADR = ISO_IEC_9796_2_SCHEME_1.class.getDeclaredField("PADR");
    PADR.setAccessible(true);
    byte fieldValue = (byte) PADR.get(scheme);

    assertEquals(fieldValue, encodedMessage[encodedMessage.length - 1],
        "The final byte of tzhe encoded message should be PADR or 0xBC");
  }

  @ParameterizedTest
  @MethodSource("provableOrStandardParameters")
  void testMessagePlacementPartRecovery(Key key, Boolean isProvablySecureParams) throws Exception {
    if (isProvablySecureParams == null) {
      scheme = new ISO_IEC_9796_2_SCHEME_1(key);
    } else {
      scheme = new ISO_IEC_9796_2_SCHEME_1(key, isProvablySecureParams);

      Field emLen = SigScheme.class.getDeclaredField("emLen");
      emLen.setAccessible(true);
      int emLenVal = (int) emLen.get(scheme);
      Field hashSize = SigScheme.class.getDeclaredField("hashSize");
      hashSize.setAccessible(true);
      int hashSizeVal = (int) hashSize.get(scheme);
      assertEquals((emLenVal + 1) / 2, hashSizeVal);
    }
    byte[] message = "Test message".getBytes();
    byte[] message2 = ("Test message for signing Test message for signing Test mes"
        + "sage for signing Test message for signing Test message for signing Test message for signi"
        + "ng Test message for signing Test message for signing Test message for signing Test message "
        + "for signing Test message for signingTest message for signing Test message for signingTest mes"
        + "sage for signingTest message for signingTest message for signingTest message for "
        + "signingv Test message for signing Test message for signing Test message for signing Test"
        + " message for signing Test message for signing Test message for signing Test message for signing").getBytes();

    Method encodeMethod = ISO_IEC_9796_2_SCHEME_1.class.getMethod("encodeMessage", byte[].class);
    encodeMethod.setAccessible(true);
    byte[] EM = (byte[]) encodeMethod.invoke(scheme, (Object) message2);
    Field emLen = SigScheme.class.getDeclaredField("emLen");
    emLen.setAccessible(true);
    int emLenVal = (int) emLen.get(scheme);
    Field emBits = SigScheme.class.getDeclaredField("emBits");
    emBits.setAccessible(true);
    int emBitsVal = (int) emBits.get(scheme);
    int hashSize = isProvablySecureParams != null ? 64 : 32;

    int hashStart = emLenVal - hashSize - 1;
    int mStart = 0;
    for (mStart = 0; mStart != emLenVal; mStart++) {
      if (((EM[mStart] & 0x0f) ^ 0x0a) == 0) {
        break;
      }
    }
    mStart++;

    byte[] m1Actual = Arrays.copyOfRange(EM, mStart, hashStart);

    int availableSpace = (hashSize + message2.length) * 8 + 8 + 4 - emBitsVal;
    int messageLength = Math.min(message2.length, message2.length - ((availableSpace + 7) / 8) - 1);
    byte[] expectedRecoveryMessage = new byte[messageLength];
    System.arraycopy(message2, 0, expectedRecoveryMessage, 0, messageLength);
    assertArrayEquals(expectedRecoveryMessage, m1Actual,
        "The recoverable message (m1) should be correctly placed in the encoded message.");
  }

  @ParameterizedTest
  @MethodSource("provableOrStandardParameters")
  void testMessagePlacementFullRecovery(Key key, Boolean isProvablySecureParams) throws Exception {
    if (isProvablySecureParams == null) {
      scheme = new ISO_IEC_9796_2_SCHEME_1(key);
    } else {
      scheme = new ISO_IEC_9796_2_SCHEME_1(key, isProvablySecureParams);

      Field emLen = SigScheme.class.getDeclaredField("emLen");
      emLen.setAccessible(true);
      int emLenVal = (int) emLen.get(scheme);
      Field hashSize = ISO_IEC_9796_2_SCHEME_1.class.getDeclaredField("hashSize");
      hashSize.setAccessible(true);
      int hashSizeVal = (int) hashSize.get(scheme);
      assertEquals((emLenVal + 1) / 2, hashSizeVal);
    }
    byte[] message = "Test message".getBytes();

    Method encodeMethod = ISO_IEC_9796_2_SCHEME_1.class.getMethod("encodeMessage", byte[].class);
    encodeMethod.setAccessible(true);
    byte[] EM = (byte[]) encodeMethod.invoke(scheme, (Object) message);
    Field emLen = SigScheme.class.getDeclaredField("emLen");
    emLen.setAccessible(true);
    int emLenVal = (int) emLen.get(scheme);
    Field emBits = SigScheme.class.getDeclaredField("emBits");
    emBits.setAccessible(true);
    int emBitsVal = (int) emBits.get(scheme);
    int hashSize = isProvablySecureParams != null ? 64 : 32;

    int hashStart = emLenVal - hashSize - 1;
    int mStart = 0;
    for (mStart = 0; mStart != emLenVal; mStart++) {
      if (((EM[mStart] & 0x0f) ^ 0x0a) == 0) {
        break;
      }
    }
    mStart++;

    byte[] m1Actual = Arrays.copyOfRange(EM, mStart, hashStart);

    int availableSpace = (hashSize + message.length) * 8 + 8 + 4 - emBitsVal;
    int messageLength = Math.min(message.length, message.length - ((availableSpace + 7) / 8) - 1);
    byte[] expectedRecoveryMessage = new byte[messageLength];
    System.arraycopy(message, 0, expectedRecoveryMessage, 0, messageLength);
    assertArrayEquals(expectedRecoveryMessage, m1Actual,
        "The recoverable message (m1) should be correctly placed in the encoded message.");
  }

  @ParameterizedTest
  @MethodSource("provableOrStandardParameters")
  public void testHashInEncodedMessage(Key key, Boolean isProvablySecureParams)
      throws NoSuchAlgorithmException, DataFormatException, NoSuchFieldException, IllegalAccessException {
    int hashSizeVal = 0;
    if (isProvablySecureParams == null) {
      scheme = new ISO_IEC_9796_2_SCHEME_1(key);
      Field hashSize = ISO_IEC_9796_2_SCHEME_1.class.getDeclaredField("hashSize");
      hashSize.setAccessible(true);
      hashSizeVal = (int) hashSize.get(scheme);
    } else {
      scheme = new ISO_IEC_9796_2_SCHEME_1(key, isProvablySecureParams);

      Field emLen = SigScheme.class.getDeclaredField("emLen");
      emLen.setAccessible(true);
      int emLenVal = (int) emLen.get(scheme);
      Field hashSize = ISO_IEC_9796_2_SCHEME_1.class.getDeclaredField("hashSize");
      hashSize.setAccessible(true);
      hashSizeVal = (int) hashSize.get(scheme);
      assertEquals((emLenVal + 1) / 2, hashSizeVal);
    }
    // Create the message
    byte[] message = "Test message".getBytes();
    byte[] message2 = ("Test message for signing Test message for signing Test mes"
        + "sage for signing Test message for signing Test message for signing Test message for signi"
        + "ng Test message for signing Test message for signing Test message for signing Test message "
        + "for signing Test message for signingTest message for signing Test message for signingTest mes"
        + "sage for signingTest message for signingTest message for signingTest message for "
        + "signingv Test message for signing Test message for signing Test message for signing Test"
        + " message for signing Test message for signing Test message for signing Test message for signing").getBytes();

    // Hash the message using the same algorithm as the scheme
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    byte[] messageHash =
        isProvablySecureParams != null ? new MGF1(md).generateMask(md.digest(message2), 64)
            : md.digest(message2);

    // Encode the message using the scheme
    byte[] encodedMessage = scheme.encodeMessage(message2);

    byte[] extractedHash = Arrays.copyOfRange(encodedMessage,
        encodedMessage.length - hashSizeVal - 1,
        encodedMessage.length - 1);

    assertArrayEquals(messageHash, extractedHash,
        "The hash in the encoded message does not match the expected hash.");
  }

  @ParameterizedTest
  @MethodSource("provableOrStandardParameters")
  void testSign(Key key, Boolean isProvablySecureParams)
      throws DataFormatException, NoSuchFieldException, IllegalAccessException, NoSuchAlgorithmException {
    if (isProvablySecureParams == null) {
      scheme = new ISO_IEC_9796_2_SCHEME_1(key);
    } else {
      scheme = new ISO_IEC_9796_2_SCHEME_1(key, isProvablySecureParams);

      Field emLen = SigScheme.class.getDeclaredField("emLen");
      emLen.setAccessible(true);
      int emLenVal = (int) emLen.get(scheme);
      Field hashSize = ISO_IEC_9796_2_SCHEME_1.class.getDeclaredField("hashSize");
      hashSize.setAccessible(true);
      int hashSizeVal = (int) hashSize.get(scheme);
      assertEquals((emLenVal + 1) / 2, hashSizeVal);
    }
    byte[] message = "Test message".getBytes();
    byte[] message2 = ("Test message for signing Test message for signing Test mes"
        + "sage for signing Test message for signing Test message for signing Test message for signi"
        + "ng Test message for signing Test message for signing Test message for signing Test message "
        + "for signing Test message for signingTest message for signing Test message for signingTest mes"
        + "sage for signingTest message for signingTest message for signingTest message for "
        + "signingv Test message for signing Test message for signing Test message for signing Test"
        + " message for signing Test message for signing Test message for signing Test message for signing").getBytes();
    byte[] signedMessage = scheme.sign(message2);

    Field m2Len = ISO_IEC_9796_2_SCHEME_1.class.getDeclaredField("m2Len");
    m2Len.setAccessible(true);
    int m2LenVal = (int) m2Len.get(scheme);

    Field m1Len = ISO_IEC_9796_2_SCHEME_1.class.getDeclaredField("m1Len");
    m1Len.setAccessible(true);
    int m1LenVal = (int) m1Len.get(scheme);

    byte[] latter;
    if (m2LenVal > 0) {
      latter = Arrays.copyOfRange(message2, m1LenVal - m2LenVal, m1LenVal);
    } else {
      // If m2Length is 0, then m2 is empty
      latter = new byte[0];
    }

    assertArrayEquals(latter, scheme.getNonRecoverableM(),
        "m2 should match the latter part of the original message.");

  }

  @ParameterizedTest
  @MethodSource("provableOrStandardParameters")
  void testSignAndVerifyRoundTrip(Key key, Boolean isProvablySecureParams) throws Exception {
    if (isProvablySecureParams == null) {
      scheme = new ISO_IEC_9796_2_SCHEME_1(key);
    } else {
      scheme = new ISO_IEC_9796_2_SCHEME_1(key, isProvablySecureParams);

      Field emLen = SigScheme.class.getDeclaredField("emLen");
      emLen.setAccessible(true);
      int emLenVal = (int) emLen.get(scheme);
      Field hashSize = ISO_IEC_9796_2_SCHEME_1.class.getDeclaredField("hashSize");
      hashSize.setAccessible(true);
      int hashSizeVal = (int) hashSize.get(scheme);
      assertEquals((emLenVal + 1) / 2, hashSizeVal);
    }
    for (int i = 0; i < 10; i++) {
      KeyPair keyPair = new GenRSA(2, new int[]{512, 512}).generateKeyPair();
      ISO_IEC_9796_2_SCHEME_1 schemeForSigning = new ISO_IEC_9796_2_SCHEME_1(
          keyPair.getPrivateKey());
      ISO_IEC_9796_2_SCHEME_1 schemeForVerifying = new ISO_IEC_9796_2_SCHEME_1(
          keyPair.getPublicKey());

      byte[] message = "Test message".getBytes();
      byte[] message2 = ("Test message for signing Test message for signing Test mes"
          + "sage for signing Test message for signing Test message for signing Test message for signi"
          + "ng Test message for signing Test message for signing Test message for signing Test message "
          + "for signing Test message for signingTest message for signing Test message for signingTest mes"
          + "sage for signingTest message for signingTest message for signingTest message for "
          + "signingv Test message for signing Test message for signing Test message for signing Test"
          + " message for signing Test message for signing Test message for signing Test message for signing").getBytes();

      byte[] signedMessage = schemeForSigning.sign(message);
      byte[] nonRecoverableM = schemeForSigning.getNonRecoverableM();

      System.out.println("Signed message (signature): " + Arrays.toString(signedMessage));

      System.out.println("non recoverable message (m2): " + Arrays.toString(nonRecoverableM));

      boolean isValidSignature = schemeForVerifying.verifyMessage(nonRecoverableM, signedMessage);

      System.out.println("Is signature valid, recovery 1? " + isValidSignature);
      // assertArrayEquals(new byte[]{0, (byte) 999}, recovery.getRecoveredMessage());
      if (schemeForVerifying.getRecoverableM() != null) {
        System.out.println(
            "Recovered message: " + new String(schemeForVerifying.getRecoverableM()));
      } else {
        System.out.println("No message was recovered.");
      }
      // Truncate the message if it's too long
      int availableSpace = 128 - 3 - 32 - 1;
      int messageLength = Math.min(message.length, availableSpace);
      byte[] expectedRecoveryMessage = new byte[messageLength];

      // Copy the most significant bytes into the new array
      // System.arraycopy(message, 0, expectedRecoveryMessage, 0, messageLength);
      //  assertEquals(new String(recovery.getRecoveredMessage()), new String(message2));
      //assertArrayEquals(expectedRecoveryMessage, recovery.getRecoveredMessage());
      assertTrue(isValidSignature);

    }
  }

  @ParameterizedTest
  @MethodSource("provableOrStandardParameters")
  void testVerificationFailsForInvalidSignature(Key key, Boolean isProvablySecureParams)
      throws Exception {
    if (isProvablySecureParams == null) {
      scheme = new ISO_IEC_9796_2_SCHEME_1(key);
    } else {
      scheme = new ISO_IEC_9796_2_SCHEME_1(key, isProvablySecureParams);

      Field emLen = SigScheme.class.getDeclaredField("emLen");
      emLen.setAccessible(true);
      int emLenVal = (int) emLen.get(scheme);
      Field hashSize = ISO_IEC_9796_2_SCHEME_1.class.getDeclaredField("hashSize");
      hashSize.setAccessible(true);
      int hashSizeVal = (int) hashSize.get(scheme);
      assertEquals((emLenVal + 1) / 2, hashSizeVal);
    }
    KeyPair keyPair = new GenRSA(2, new int[]{512, 512}).generateKeyPair();
    ISO_IEC_9796_2_SCHEME_1 schemeForVerifying = new ISO_IEC_9796_2_SCHEME_1(
        keyPair.getPublicKey());

    byte[] message = "test message".getBytes();
    byte[] invalidSignature = new byte[128]; // Assuming RSA 1024-bit key
    new SecureRandom().nextBytes(invalidSignature); // Fill with random data

    boolean result = schemeForVerifying.verifyMessage(new byte[0], invalidSignature);
    assertFalse(result);
  }


  @ParameterizedTest
  @MethodSource("provableOrStandardParameters")
  void testVerificationFailsForAlteredSignature(Key key, Boolean isProvablySecureParams)
      throws Exception {
    if (isProvablySecureParams == null) {
      scheme = new ISO_IEC_9796_2_SCHEME_1(key);
    } else {
      scheme = new ISO_IEC_9796_2_SCHEME_1(key, isProvablySecureParams);

      Field emLen = SigScheme.class.getDeclaredField("emLen");
      emLen.setAccessible(true);
      int emLenVal = (int) emLen.get(scheme);
      Field hashSize = ISO_IEC_9796_2_SCHEME_1.class.getDeclaredField("hashSize");
      hashSize.setAccessible(true);
      int hashSizeVal = (int) hashSize.get(scheme);
      assertEquals((emLenVal + 1) / 2, hashSizeVal);
    }
    KeyPair keyPair = new GenRSA(2, new int[]{512, 512}).generateKeyPair();
    ISO_IEC_9796_2_SCHEME_1 schemeForSigning = new ISO_IEC_9796_2_SCHEME_1(
        keyPair.getPrivateKey());
    ISO_IEC_9796_2_SCHEME_1 schemeForVerifying = new ISO_IEC_9796_2_SCHEME_1(
        keyPair.getPublicKey());

    byte[] message = "test message".getBytes();
    byte[] signatureWithM2 = schemeForSigning.sign(message);

    // Alter the signature (flip the last bit)
    signatureWithM2[signatureWithM2.length - 1] ^= 1;

    boolean result = schemeForVerifying.verifyMessage(schemeForSigning.getNonRecoverableM(),
        signatureWithM2);
    assertFalse(result);
  }

  @ParameterizedTest
  @MethodSource("provableOrStandardParameters")
  void testVerificationWithCorrectAndIncorrectKeys(Key key, Boolean isProvablySecureParams)
      throws Exception {
    if (isProvablySecureParams == null) {
      scheme = new ISO_IEC_9796_2_SCHEME_1(key);
    } else {
      scheme = new ISO_IEC_9796_2_SCHEME_1(key, isProvablySecureParams);

      Field emLen = SigScheme.class.getDeclaredField("emLen");
      emLen.setAccessible(true);
      int emLenVal = (int) emLen.get(scheme);
      Field hashSize = ISO_IEC_9796_2_SCHEME_1.class.getDeclaredField("hashSize");
      hashSize.setAccessible(true);
      int hashSizeVal = (int) hashSize.get(scheme);
      assertEquals((emLenVal + 1) / 2, hashSizeVal);
    }
    KeyPair keyPair = new GenRSA(2, new int[]{512, 512}).generateKeyPair();
    ISO_IEC_9796_2_SCHEME_1 schemeForSigning = new ISO_IEC_9796_2_SCHEME_1(
        keyPair.getPrivateKey());

    byte[] message = "test message".getBytes();
    byte[] signatureWithM2 = schemeForSigning.sign(message);

    // Use the correct public key for verification
    ISO_IEC_9796_2_SCHEME_1 schemeForVerifyingWithCorrectKey = new ISO_IEC_9796_2_SCHEME_1(
        keyPair.getPublicKey());
    boolean resultWithCorrectKey = schemeForVerifyingWithCorrectKey.verifyMessage(
        schemeForSigning.getNonRecoverableM(), signatureWithM2);
    assertTrue(resultWithCorrectKey,
        "The signature should be valid with the correct public key.");

    // Generate a new key pair, which will have a different public key
    KeyPair keyPair2 = new GenRSA(2, new int[]{512, 512}).generateKeyPair();
    ISO_IEC_9796_2_SCHEME_1 schemeForVerifyingWithIncorrectKey = new ISO_IEC_9796_2_SCHEME_1(
        keyPair2.getPublicKey());

    // Try to verify the signature with the incorrect public key
    boolean resultWithIncorrectKey = schemeForVerifyingWithIncorrectKey.verifyMessage(
        schemeForSigning.getNonRecoverableM(), signatureWithM2);
    assertFalse(resultWithIncorrectKey);
  }


}
