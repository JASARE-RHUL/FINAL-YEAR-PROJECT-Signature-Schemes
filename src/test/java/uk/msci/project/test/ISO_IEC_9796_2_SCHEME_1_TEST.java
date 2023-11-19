package uk.msci.project.test;

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
import java.util.zip.DataFormatException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.msci.project.rsa.GenRSA;
import uk.msci.project.rsa.ISO_IEC_9796_2_SCHEME_1;
import uk.msci.project.rsa.ISO_IEC_9796_2_SCHEME_1;
import uk.msci.project.rsa.KeyPair;
import uk.msci.project.rsa.SigScheme;
import uk.msci.project.rsa.SignatureRecovery;

public class ISO_IEC_9796_2_SCHEME_1_TEST {

  private ISO_IEC_9796_2_SCHEME_1 scheme;

  @BeforeEach
  public void setup() {
    scheme = new ISO_IEC_9796_2_SCHEME_1(
        new GenRSA(2, new int[]{512, 512}).generateKeyPair().getPrivateKey());
  }

  @Test
  void testInitialBytePadding() throws Exception {
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
    assertEquals((0x60 | (0x0A & 0x0F)), encodedMessage[1],
        "The first non zero byte of the encoded message should match 0X6A for suffcicently long messages with a recoverable component.");

    byte[] encodedMessage2 = (byte[]) encodeMethod.invoke(scheme, (Object) message2);
    assertEquals((0x40 | (0x0B & 0x0F)), encodedMessage2[1],
        "The first non zero byte of the encoded message should match 0x4A for shorter message that do not have a recoverable component");
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
        "The final byte of tzhe encoded message should be PADR or 0xBC");
  }





}
