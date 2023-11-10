package uk.msci.project.test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.math.BigInteger;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
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

//  @Test
//  public void testEMSA_PKCS1_v1_5_ENCODE_PaddingString()
//      throws DataFormatException, NoSuchAlgorithmException {
//    byte[] message = "test message 3".getBytes();
//    byte[] encodedMessage = scheme.EMSA_PKCS1_v1_5_ENCODE(message);
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
//  public void testEMSA_PKCS1_v1_5_ENCODE_Separator()
//      throws DataFormatException, NoSuchAlgorithmException {
//    byte[] message = "test message 4".getBytes();
//    byte[] encodedMessage = scheme.EMSA_PKCS1_v1_5_ENCODE(message);
//    MessageDigest md = MessageDigest.getInstance("SHA-256");
//    byte[] mHash = md.digest(message);
//    int separatorIndex = encodedMessage.length - mHash.length - 1;
//
//    assertEquals(0x00, encodedMessage[separatorIndex],
//        "The byte preceding the message should be 0x00");
//}
//
//  @Test
//  public void testEMSA_PKCS1_v1_5_ENCODE_MessagePlacement()
//      throws DataFormatException, NoSuchAlgorithmException {
//    byte[] message = "test message 4".getBytes();
//    byte[] encodedMessage = scheme.EMSA_PKCS1_v1_5_ENCODE(message);
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
//  public void testEMSA_PKCS1_v1_5_ENCODE_HashIncorporation()
//      throws DataFormatException, NoSuchAlgorithmException {
//    byte[] message = "Test message 5".getBytes();
//    MessageDigest md = MessageDigest.getInstance("SHA-256");
//
//    byte[] encodedMessage = scheme.EMSA_PKCS1_v1_5_ENCODE(message);
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
  public void testEMSA_PKCS1_v1_5_ENCODE_PaddingString()
      throws DataFormatException, NoSuchAlgorithmException {
    byte[] message = "test message 7".getBytes();
    byte[] encodedMessage = scheme.EMSA_PKCS1_v1_5_ENCODE(message);
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
  public void testEMSA_PKCS1_v1_5_ENCODE_Separator()
      throws DataFormatException, NoSuchAlgorithmException {
    byte[] message = "test message 8".getBytes();
    byte[] encodedMessage = scheme.EMSA_PKCS1_v1_5_ENCODE(message);
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    byte[] mHash = md.digest(message);
    byte[] digestInfo = scheme.createDigestInfo(mHash);
    int tLen = digestInfo.length;
    int separatorIndex = encodedMessage.length - tLen - 1;

    assertEquals(0x00, encodedMessage[separatorIndex],
        "The byte preceding the message should be 0x00");
  }

  @Test
  public void testEMSA_PKCS1_v1_5_ENCODE_MessagePlacement()
      throws DataFormatException, NoSuchAlgorithmException {
    byte[] message = "test message 9".getBytes();
    byte[] encodedMessage = scheme.EMSA_PKCS1_v1_5_ENCODE(message);
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
  public void testEMSA_PKCS1_v1_5_ENCODE_HashIncorporation()
      throws DataFormatException, NoSuchAlgorithmException {
    byte[] message = "Test message 10".getBytes();
    MessageDigest md = MessageDigest.getInstance("SHA-256");

    byte[] encodedMessage = scheme.EMSA_PKCS1_v1_5_ENCODE(message);
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
  public void testOS2IPWithEmptyArray() {
    byte[] emptyArray = new byte[0];
    BigInteger result = scheme.OS2IP(emptyArray);
    assertEquals(BigInteger.ZERO, result, "An empty byte array should convert to zero");
  }

  @Test
  public void testOS2IPWithNonEmptyArray() {
    byte[] byteArray = {0x01, 0x02, 0x03, 0x04}; // Example byte array
    BigInteger expectedResult = new BigInteger(1, byteArray);
    BigInteger result = scheme.OS2IP(byteArray);

    assertEquals(expectedResult, result, "Byte array should correctly convert to BigInteger");
  }

  @Test
  public void testOS2IPWithLargeNumber() {
    byte[] largeNumberArray = new byte[]{(byte) 0x8f, (byte) 0xad, (byte) 0xb8, (byte) 0xe0};
    BigInteger expectedResult = new BigInteger(1, largeNumberArray);
    BigInteger result = scheme.OS2IP(largeNumberArray);

    assertEquals(expectedResult, result, "Large number byte array should correctly convert to BigInteger");
  }

  @Test
  public void testOS2IPWithLeadingZeros() {
    byte[] byteArrayWithZeros = {0x00, 0x00, 0x01, 0x02};
    BigInteger expectedResult = new BigInteger(1, byteArrayWithZeros);
    BigInteger result = scheme.OS2IP(byteArrayWithZeros);

    assertEquals(expectedResult, result, "Byte array with leading zeros should correctly convert to BigInteger");
  }




}




