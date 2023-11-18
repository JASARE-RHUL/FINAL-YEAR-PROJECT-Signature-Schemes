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
    Method encodeMethod = ISO_IEC_9796_2_SCHEME_1.class.getDeclaredMethod("encodeMessage", byte[].class);
    encodeMethod.setAccessible(true);
    byte[] encodedMessage = (byte[]) encodeMethod.invoke(scheme, (Object) message);


    assertEquals( 0x6A, encodedMessage[1],
        "The first non zero byte of the encoded message should match PADL.");
  }


}
