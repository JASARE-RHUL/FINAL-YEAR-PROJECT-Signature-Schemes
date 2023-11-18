package uk.msci.project.test;

import static org.junit.Assert.assertFalse;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.zip.DataFormatException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.msci.project.rsa.GenRSA;
import uk.msci.project.rsa.ISO_IEC_9796_2_SCHEME_1;
import uk.msci.project.rsa.ISO_IEC_9796_2_SCHEME_1_PR;
import uk.msci.project.rsa.RSASSA_PKCS1_v1_5;
import uk.msci.project.rsa.RSASSA_PKCS1_v1_5;
import uk.msci.project.rsa.KeyPair;
import uk.msci.project.rsa.SigScheme;
import uk.msci.project.rsa.SignatureRecovery;

public class ISO_IEC_9796_2_SCHEME_1_PR_TEST {

  private ISO_IEC_9796_2_SCHEME_1_PR scheme;

  @BeforeEach
  public void setup() {
    scheme = new ISO_IEC_9796_2_SCHEME_1_PR(
        new GenRSA(2, new int[]{512, 512}).generateKeyPair().getPrivateKey());
  }

  @Test
  void testInitialBytePadding() throws Exception {
    byte[] message = "test message test message test message test message test message test message test message test message test message test message test message test message test message test message test message test message test message test message test message test message test message test message test message 1".getBytes();
    Method encodeMethod = ISO_IEC_9796_2_SCHEME_1.class.getDeclaredMethod("encodeMessage",
        byte[].class);
    encodeMethod.setAccessible(true);
    byte[] encodedMessage = (byte[]) encodeMethod.invoke(scheme, (Object) message);

    assertEquals(0x6A, encodedMessage[1],
        "The first non zero byte of the encoded message should match PADL.");
  }

  @Test
  void testFinalBytePadding() throws Exception {
    byte[] message = "test".getBytes();
    Method encodeMethod = ISO_IEC_9796_2_SCHEME_1.class.getDeclaredMethod("encodeMessage",
        byte[].class);
    encodeMethod.setAccessible(true);
    byte[] encodedMessage = (byte[]) encodeMethod.invoke(scheme, (Object) message);

    Field PADR = ISO_IEC_9796_2_SCHEME_1.class.getDeclaredField("PADR");
    PADR.setAccessible(true);
    byte fieldValue = (byte) PADR.get(scheme);

    assertEquals(fieldValue, encodedMessage[encodedMessage.length - 1],
        "The final byte of the encoded message should be PADR.");
  }

  @Test
  void testMessagePlacement() throws Exception {
    byte[] message = "Test message".getBytes();
    byte[] message2 = ("Test message for signing Test message for signing Test mes"
        + "sage for signing Test message for signing Test message for signing Test message for signi"
        + "ng Test message for signing Test message for signing Test message for signing Test message "
        + "for signing Test message for signingTest message for signing Test message for signingTest mes"
        + "sage for signingTest message for signingTest message for signingTest message for "
        + "signingv Test message for signing Test message for signing Test message for signing Test"
        + " message for signing Test message for signing Test message for signing Test message for signing").getBytes();

    Method encodeMethod = ISO_IEC_9796_2_SCHEME_1_PR.class.getMethod("encodeMessage", byte[].class);
    encodeMethod.setAccessible(true);
    byte[] EM = (byte[]) encodeMethod.invoke(scheme, (Object) message2);
    Field emLen = SigScheme.class.getDeclaredField("emLen");
    emLen.setAccessible(true);
    int emLenVal = (int) emLen.get(scheme);

    int hashStartIndex = emLenVal - 1 - 32;

    // Calculate the length of m1
    int m1Length = hashStartIndex - 3; // Subtracting bytes for 0x06, 0xA0

    // Create array for m1
    byte[] m1Candidate = new byte[m1Length];

    // Start copying from the third byte of EM, as first two bytes are padding
    System.arraycopy(EM, 2, m1Candidate, 0, m1Length);

    // Trim potential trailing zeros from m1
    int m1EndIndex = m1Candidate.length;
    while (m1EndIndex > 0 && m1Candidate[m1EndIndex - 1] == 0) {
      m1EndIndex--;
    }

    byte[] m1Actual = Arrays.copyOfRange(m1Candidate, 0, m1EndIndex);

    int availableSpace = emLenVal - 3 - 32 - 1;
    int messageLength = Math.min(message2.length, availableSpace);
    byte[] expectedRecoveryMessage = new byte[messageLength];
    System.arraycopy(message2, 0, expectedRecoveryMessage, 0, messageLength);
    assertArrayEquals(expectedRecoveryMessage, m1Actual,
        "The recoverable message (m1) should be correctly placed in the encoded message.");
  }


  @Test
  public void testHashInEncodedMessage() throws NoSuchAlgorithmException, DataFormatException {
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
    byte[] messageHash = md.digest(message2);

    // Encode the message using the scheme
    byte[] encodedMessage = scheme.encodeMessage(message2);

    byte[] extractedHash = Arrays.copyOfRange(encodedMessage, encodedMessage.length - 33,
        encodedMessage.length - 1);

    assertArrayEquals(messageHash, extractedHash,
        "The hash in the encoded message does not match the expected hash.");
  }

  @Test
  void testSign()
      throws DataFormatException, NoSuchFieldException, IllegalAccessException, NoSuchAlgorithmException {
    byte[] message = "Test message".getBytes();
    byte[] message2 = ("Test message for signing Test message for signing Test mes"
        + "sage for signing Test message for signing Test message for signing Test message for signi"
        + "ng Test message for signing Test message for signing Test message for signing Test message "
        + "for signing Test message for signingTest message for signing Test message for signingTest mes"
        + "sage for signingTest message for signingTest message for signingTest message for "
        + "signingv Test message for signing Test message for signing Test message for signing Test"
        + " message for signing Test message for signing Test message for signing Test message for signing").getBytes();
    byte[][] signedMessage = scheme.extendedSign(message);

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

    assertArrayEquals(latter, signedMessage[1],
        "m2 should match the latter part of the original message.");

  }

  @Test
  void testSignAndVerifyRoundTrip() throws Exception {
    for (int i = 0; i < 100; i++) {
      KeyPair keyPair = new GenRSA(2, new int[]{512, 512}).generateKeyPair();
      ISO_IEC_9796_2_SCHEME_1_PR schemeForSigning = new ISO_IEC_9796_2_SCHEME_1_PR(
          keyPair.getPrivateKey());
      ISO_IEC_9796_2_SCHEME_1_PR schemeForVerifying = new ISO_IEC_9796_2_SCHEME_1_PR(
          keyPair.getPublicKey());

      byte[] message = "Test message".getBytes();
      byte[] message2 = ("Test message for signing Test message for signing Test mes"
          + "sage for signing Test message for signing Test message for signing Test message for signi"
          + "ng Test message for signing Test message for signing Test message for signing Test message "
          + "for signing Test message for signingTest message for signing Test message for signingTest mes"
          + "sage for signingTest message for signingTest message for signingTest message for "
          + "signingv Test message for signing Test message for signing Test message for signing Test"
          + " message for signing Test message for signing Test message for signing Test message for signing").getBytes();

      byte[][] signedMessage = schemeForSigning.extendedSign(message);

      System.out.println("Signed message (signature): " + Arrays.toString(signedMessage[0]));

      System.out.println("non recoverable message (m2): " + Arrays.toString(signedMessage[1]));

      SignatureRecovery recovery = schemeForVerifying.verifyMessageISO(signedMessage[1],
          signedMessage[0]);
      SignatureRecovery recovery2 = schemeForVerifying.verifyMessageISO(signedMessage[1],
          signedMessage[0]);

      System.out.println("Is signature valid, recovery 1? " + recovery.isValid());
      // assertArrayEquals(new byte[]{0, (byte) 999}, recovery.getRecoveredMessage());
      if (recovery.getRecoveredMessage() != null) {
        System.out.println("Recovered message: " + new String(recovery.getRecoveredMessage()));
      } else {
        System.out.println("No message was recovered.");
      }
      // Truncate the message if it's too long
      int availableSpace = 128 - 3 - 32 - 1;
      int messageLength = Math.min(message.length, availableSpace);
      byte[] expectedRecoveryMessage = new byte[messageLength];

      // Copy the most significant bytes into the new array
      System.arraycopy(message, 0, expectedRecoveryMessage, 0, messageLength);
      assertArrayEquals(expectedRecoveryMessage, recovery.getRecoveredMessage());
      assertTrue(recovery.isValid());

    }


  }


}
