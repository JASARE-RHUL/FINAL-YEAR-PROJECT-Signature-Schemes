package uk.msci.project.test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.math.BigInteger;

import java.util.Arrays;
import java.util.zip.DataFormatException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.msci.project.rsa.GenRSA;
import uk.msci.project.rsa.Key;
import uk.msci.project.rsa.PrivateKey;
import uk.msci.project.rsa.RSASSA_PKCS1_v1_5;

public class RSASSA_PKCS1_v1_5_TEST {

  private RSASSA_PKCS1_v1_5 scheme;

  @BeforeEach
  // Before each test is run, clear any created key files.
  public void setup() {
    scheme = new RSASSA_PKCS1_v1_5(
        new GenRSA(1024).generateKeyPair().getPrivateKey());
  }

  @Test
  void testEMSA_PKCS1_v1_5_ENCODE_InitialZero() throws DataFormatException {
    byte[] message = "test message 1".getBytes();
    byte[] encodedMessage = scheme.EMSA_PKCS1_v1_5_ENCODE(message);

    assertEquals(0x00, encodedMessage[0], "The first byte of the encoded message should be 0x00");

  }

  @Test
  void testEMSA_PKCS1_v1_5_ENCODE_BlockType() throws DataFormatException {
    byte[] message = "test message 2".getBytes();
    byte[] encodedMessage = scheme.EMSA_PKCS1_v1_5_ENCODE(message);

    assertEquals(0x01, encodedMessage[1], "The block type byte should be 0x01");
  }

  @Test
  public void testEMSA_PKCS1_v1_5_ENCODE_PaddingString() throws DataFormatException {
    byte[] message = "test message 3".getBytes();
    byte[] encodedMessage = scheme.EMSA_PKCS1_v1_5_ENCODE(message);

    for (int i = 2; i < encodedMessage.length - message.length - 1; i++) {
      assertEquals((byte) 0xFF, encodedMessage[i],
          "Padding byte at index " + i + " should be 0xFF");
    }
  }

  @Test
  public void testEMSA_PKCS1_v1_5_ENCODE_Separator() throws DataFormatException {
    byte[] message = "test message 4".getBytes();
    byte[] encodedMessage = scheme.EMSA_PKCS1_v1_5_ENCODE(message);
    int separatorIndex = encodedMessage.length - message.length - 1;

    assertEquals(0x00, encodedMessage[separatorIndex],
        "The byte preceding the message should be 0x00");
  }

  @Test
  public void testEMSA_PKCS1_v1_5_ENCODE_MessagePlacement() throws DataFormatException {
    byte[] message = "test message 4".getBytes();
    byte[] encodedMessage = scheme.EMSA_PKCS1_v1_5_ENCODE(message);
    byte[] messageInEM = Arrays.copyOfRange(encodedMessage, encodedMessage.length - message.length,
        encodedMessage.length);

    assertArrayEquals(message, messageInEM,
        "The message should be correctly placed at the end of the encoded message");
  }


}
