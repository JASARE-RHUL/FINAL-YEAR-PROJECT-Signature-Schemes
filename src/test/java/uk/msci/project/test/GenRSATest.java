package uk.msci.project.test;

import static java.lang.Math.max;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;


import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.ISO9796d2Signer;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import uk.msci.project.rsa.ByteArrayConverter;
import uk.msci.project.rsa.GenRSA;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.Security;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;


class GenRSATest {

//  @Test
//    // Test 1
//    // Create a constructor for a newly created GenRSATest class that enables a generation process to be
//    // initialised for generating a key with a specified key size.
//    // Enable the key size to be retrieved through a getter.
//  void testKeySize() {
//    int expectedKeySize = 1024;
//    GenRSA genRSA = new GenRSA(2, new int[]{512, 512});
//
//    // Assert
//    assertEquals(expectedKeySize, genRSA.getKeySize(),
//        "The getKeySize method should return the correct key size");
//  }

  @Test
    // Test 2
    // Enable the GenRSA constructor to only permit positive integers
    // between 1024 and 7680 as valid key sizes.
  void testInvalidKeySize()
      throws NoSuchAlgorithmException, IOException, CryptoException, InvalidKeySpecException {
    Security.addProvider(new BouncyCastleProvider());

    KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
    keyPairGen.initialize(2048);
    KeyPair pair = keyPairGen.generateKeyPair();

    RSAPublicKey pubKey = (RSAPublicKey) pair.getPublic();
    RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) pair.getPrivate();

    RSAKeyParameters publicKeyParams = new RSAKeyParameters(false, pubKey.getModulus(), pubKey.getPublicExponent());
    RSAKeyParameters privateKeyParams = new RSAKeyParameters(true, privKey.getModulus(), privKey.getPrivateExponent());
    // Prepare the Signer
    AsymmetricBlockCipher rsaEngine = new RSAEngine();
    ISO9796d2Signer signer = new ISO9796d2Signer(rsaEngine, new SHA256Digest());

    // Sign the Data
    signer.init(true, privateKeyParams);
    byte[] message = "Hello, World!".getBytes();
    byte[] message2 = ("Test message for signing Test message for signing Test mes"
        + "sage for signing Test message for signing Test message for signing Test message for signi"
        + "ng Test message for signing Test message for signing Test message for signing Test message "
        + "for signing Test message for signingTest message for signing Test message for signingTest mes"
        + "sage for signingTest message for signingTest message for signingTest message for "
        + "signingv Test message for signing Test message for signing Test message for signing Test"
        + " message for signing Test message for signing Test message for signing Test message for signing").getBytes();
    signer.update(message2, 0, message2.length);
    byte[] signature = signer.generateSignature();

    ISO9796d2Signer signer2 = new ISO9796d2Signer(rsaEngine, new SHA256Digest());

    // Sign the Data
    //signer2.init(true, publicKeyParams);
    int availableSpace = (32 + message2.length) * 8 + 8 + 4 - 1024;
    // Verify the Signature
    signer.init(false, publicKeyParams);
    int messageLength = Math.min(message2.length, message2.length - ((availableSpace + 7) / 8));
    // m2 comprises the non-recoverable message portion
    int m2Len = max(message2.length - messageLength, 0);
    signer.update(message2, 0, message2.length);
    boolean isSignatureValid = signer.verifySignature(signature);

    String ass =  new String(signer.getRecoveredMessage());
    int n = signer.getRecoveredMessage().length;
    System.out.println("Signature valid: " + isSignatureValid+ new String(signer.getRecoveredMessage()));
  }


//  @Test
//  void testValidKeySize() {
//    int k = 2; // Number of primes
//
//    // Valid lambda arrays
//    int[] lambda7680 = {3840, 3840}; // Sum is 7680
//    GenRSA genRSA = new GenRSA(k, lambda7680);
//    assertEquals(7680, genRSA.getKeySize(),
//        "The getKeySize method should return the correct key size");
//
//    int[] lambda2048 = {1024, 1024}; // Sum is 2048
//    GenRSA genRSA2 = new GenRSA(k, lambda2048);
//    assertEquals(2048, genRSA2.getKeySize(),
//        "The getKeySize method should return the correct key size");
//
//    GenRSA genRSA3 = new GenRSA(k, new int[]{1536, 1536});
//    assertEquals(3072, genRSA3.getKeySize(),
//        "The getKeySize method should return the correct key size");
//
//    GenRSA genRSA4 = new GenRSA(k, new int[]{2048, 2048});
//    assertEquals(4096, genRSA4.getKeySize(),
//        "The getKeySize method should return the correct key size");
//  }
//
//
//  @Test
//    // Test 5
//    // Create a method,generatePrimeComponents that generates two probable primes
//    // intended to comprise the prime factors of the modulus N
//  void testGeneratePrimeComponents() {
//    int k = 2; // Number of primes
//    int[] lambda = {512, 512};
//    GenRSA genRSA = new GenRSA(k, lambda);
//    BigInteger[] primeComponents = genRSA.generatePrimeComponents();
//
//    assertEquals(75, genRSA.getCertainty(),
//        "The certainty level should match the default certainty level.");
//
//// Check that each generated component is a probable prime
//    for (BigInteger prime : primeComponents) {
//      assertTrue(prime.isProbablePrime(genRSA.getCertainty()),
//          "Each component should be a probable prime with the given certainty.");
//    }
//
//  }
//
//  @Test
//    // Test 6
//    // Create a method,computePhi intended to compute the
//    // Computes the Euler's totient function of the Modulus N
//  void testComputePhi() {
//    int k = 3;
//    int[] lambda = {341, 341,
//        342};
//    GenRSA genRSA = new GenRSA(k, lambda);
//    BigInteger[] primeComponents = genRSA.generatePrimeComponents();
//
//    BigInteger expectedPhi = BigInteger.ONE;
//    for (BigInteger prime : primeComponents) {
//      expectedPhi = expectedPhi.multiply(prime.subtract(BigInteger.ONE));
//    }
//
//    // Act
//    BigInteger actualPhi = genRSA.computePhi(primeComponents);
//
//    // Assert
//    assertEquals(expectedPhi, actualPhi,
//        "The computePhi method should return the correct Euler's totient function result for multiple primes.");
//  }
//
//
//  @Test
//    // Test 7
//    // Create a method, computeE intended to compute the
//    // public exponent {@code e} for public key component in the RSA Key pair
//    // Tests that e and euler's totient are co prime
//  void testComputeE() {
//    int k = 3; // Example for three prime factors
//    int[] lambda = {341, 341, 342}; // Example bit lengths
//    GenRSA genRSA = new GenRSA(k, lambda);
//    BigInteger[] primeComponents = genRSA.generatePrimeComponents();
//    BigInteger phi = genRSA.computePhi(primeComponents);
//    BigInteger e = genRSA.computeE(phi);
//    assertEquals(BigInteger.ONE, e.gcd(phi), "The public exponent 'e' and 'phi' should be coprime");
//  }
//
//  @Test
//  void testComputeEIsGreaterThanOne() {
//    int k = 3;
//    int[] lambda = {341, 341, 342};
//    GenRSA genRSA = new GenRSA(k, lambda);
//    BigInteger[] primeComponents = genRSA.generatePrimeComponents();
//    BigInteger phi = genRSA.computePhi(primeComponents);
//    BigInteger e = genRSA.computeE(phi);
//
//    assertTrue(e.compareTo(BigInteger.ONE) > 0,
//        "The public exponent 'e' should be greater than one");
//  }
//
//  @Test
//  void testComputeEIsLessThanPhi() {
//    int k = 3;
//    int[] lambda = {341, 341, 342};
//    GenRSA genRSA = new GenRSA(k, lambda);
//    BigInteger[] primeComponents = genRSA.generatePrimeComponents();
//    BigInteger phi = genRSA.computePhi(primeComponents);
//    BigInteger e = genRSA.computeE(phi);
//
//    assertTrue(e.compareTo(phi) < 0, "The public exponent 'e' should be less than 'phi'");
//  }

//
//  @Test
//    // Test 10
//    // Create a method, generateKeyPair that fulfils the generation of an RSA Key pair
//  void testGenerateKeyPair() {
//    GenRSA genRSA = new GenRSA(1024);
//    BigInteger[] keyPair = genRSA.generateKeyPair();
//    BigInteger N = keyPair[0];
//    BigInteger p = keyPair[1];
//    BigInteger q = keyPair[2];
//
//
//    assertNotNull(keyPair, "The generateKeyPair method should not return null");
//    assertEquals(5, keyPair.length,
//        "The generateKeyPair method should return an array of 5 BigInteger components");
//
//    assertEquals(p.multiply(q), N,
//        "The modulus N should be the product of two prime numbers p and q");
//
//    BigInteger phi = genRSA.computePhi(p, q);
//    BigInteger e = keyPair[3];
//    BigInteger d = keyPair[4];
//    assertTrue(e.compareTo(BigInteger.ONE) > 0 && e.compareTo(phi) < 0, "1 < e < phi(N) should be true");
//    assertEquals(BigInteger.ONE, e.gcd(phi), "gcd(e, phi(N)) should be 1");
//    assertEquals(e.modInverse(phi), d, "d should be the modular multiplicative inverse of e modulo phi(N)");
//  }
//
//  @Test
//    // Test 11
//    // Create a method, generateKeyPair that fulfils the generation of an RSA Key pair
//    // Refactor the return of key components into dedicated key classes,
//    // Private and Public key comprising a Key Pair
//    //Tests that the modulus does not differ between the public and private key
//  void testGenerateKeyPair2() {
//    int k = 3;
//    int[] lambda = {341, 341, 342};
//    GenRSA genRSA = new GenRSA(k, lambda);
//    KeyPair keyPair = genRSA.generateKeyPair();
//    BigInteger pubKeyModulus = keyPair.getPublicKey().getModulus();
//
//    assertEquals(pubKeyModulus, keyPair.getPrivateKey().getModulus());
//    BigInteger expectedModulus = BigInteger.ONE;
//    for (BigInteger prime : keyPair.getPrivateKey().getPrimes()) {
//      expectedModulus = expectedModulus.multiply(prime);
//    }
//    assertEquals(expectedModulus, pubKeyModulus,
//        "The modulus N should be the product of its prime components");
//
//    assertNotNull(keyPair, "The generateKeyPair method should not return null");
//
//    BigInteger phi = keyPair.getPrivateKey().getPhi();
//    BigInteger e = keyPair.getPrivateKey().getE();
//    BigInteger d = keyPair.getPrivateKey().getExponent();
//    assertTrue(e.compareTo(BigInteger.ONE) > 0 && e.compareTo(phi) < 0,
//        "1 < e < phi(N) should be true");
//    assertEquals(BigInteger.ONE, e.gcd(phi), "gcd(e, phi(N)) should be 1");
//    assertEquals(e.modInverse(phi), d,
//        "d should be the modular multiplicative inverse of e modulo phi(N)");
//  }
//
//
//
//  @Test
//  void test() throws Exception {
//    for (int i = 0; i < 100; i++) {
//      // Generate RSA Key Pair
//      java.security.KeyPair keyPair = generateRSAKeyPair();
//      RSAPublicKeySpec publicKeySpec = KeyFactory.getInstance("RSA")
//          .getKeySpec(keyPair.getPublic(), RSAPublicKeySpec.class);
//      RSAPrivateKeySpec privateKeySpec = KeyFactory.getInstance("RSA")
//          .getKeySpec(keyPair.getPrivate(), RSAPrivateKeySpec.class);
//
//      BigInteger modulus = publicKeySpec.getModulus();
//      BigInteger publicExponent = publicKeySpec.getPublicExponent();
//      BigInteger privateExponent = privateKeySpec.getPrivateExponent();
//
//      // Original message with padding byte
//      byte[] originalMessage = prepareMessage("s");
//
//      // Adjust input for encryption
//      BigInteger messageBigInt = convertInput(true, originalMessage, 0, getInputBlockSize(true));
//
//      // Check and adjust if the message is larger than the modulus
//      if (messageBigInt.compareTo(modulus) >= 0) {
//        messageBigInt = messageBigInt.min(modulus.subtract(messageBigInt));
//      }
//
//      // Encrypt the message
//      BigInteger encryptedBigInt = messageBigInt.modPow(publicExponent, modulus);
//
//      // Decrypt the message
//      BigInteger decryptedBigInt = encryptedBigInt.modPow(privateExponent, modulus);
//
//      // Convert decrypted BigInteger back to byte array using convertOutput
//      byte[] decryptedMessage = convertOutput(false, decryptedBigInt);
//
//      // Check if the decryption is successful
//      assertArrayEquals(originalMessage, decryptedMessage);
//    }
//  }
//
//
//  /**
//   * Return the passed in value as an unsigned byte array of the specified length, padded with
//   * leading zeros as necessary..
//   *
//   * @param length the fixed length of the result
//   * @param value  the value to be converted.
//   * @return a byte array padded to a fixed length with leading zeros.
//   */
//  public static byte[] asUnsignedByteArray(int length, BigInteger value) {
//    byte[] bytes = value.toByteArray();
//    if (bytes.length == length) {
//      return bytes;
//    }
//
//    int start = (bytes[0] == 0 && bytes.length != 1) ? 1 : 0;
//    int count = bytes.length - start;
//
//    if (count > length) {
//      throw new IllegalArgumentException("standard length exceeded for value");
//    }
//
//    byte[] tmp = new byte[length];
//    System.arraycopy(bytes, start, tmp, tmp.length - count, count);
//    return tmp;
//  }
//
//  public int getInputBlockSize(boolean ass)
//  {
//
//
//    if (ass)
//    {
//      return (2048 + 7) / 8 - 1;
//    }
//    else
//    {
//      return (2045 + 7) / 8;
//    }
//  }
//
//  public BigInteger convertInput( boolean ass,
//      byte[] in,
//      int inOff,
//      int inLen)
//  {
//
//
//    byte[] block;
//
//    if (inOff != 0 || inLen != in.length)
//    {
//      block = new byte[inLen];
//
//      System.arraycopy(in, inOff, block, 0, inLen);
//    }
//    else
//    {
//      block = in;
//    }
//
//    BigInteger res = new BigInteger(1, block);
//
//    return res;
//  }
//
//  public int getOutputBlockSize(boolean ass) {
//
//    if (ass) {
//      return (2048 + 7) / 8;
//    } else {
//      return (2048 + 7) / 8 - 1;
//    }
//  }
//    public byte[] convertOutput (boolean ass, BigInteger result)
//    {
//      byte[] output = result.toByteArray();
//
//      if (ass) {
//        if (output[0] == 0 && output.length
//            > getOutputBlockSize(ass))        // have ended up with an extra zero byte, copy down.
//        {
//          byte[] tmp = new byte[output.length - 1];
//
//          System.arraycopy(output, 1, tmp, 0, tmp.length);
//
//          return tmp;
//        }
//
//        if (output.length
//            < getOutputBlockSize(ass))     // have ended up with less bytes than normal, lengthen
//        {
//          byte[] tmp = new byte[getOutputBlockSize(ass)];
//
//          System.arraycopy(output, 0, tmp, tmp.length - output.length, output.length);
//
//          return tmp;
//        }
//
//        return output;
//      } else {
//        byte[] rv;
//        if (output[0] == 0)        // have ended up with an extra zero byte, copy down.
//        {
//          rv = new byte[output.length - 1];
//
//          System.arraycopy(output, 1, rv, 0, rv.length);
//        } else        // maintain decryption time
//        {
//          rv = new byte[output.length];
//
//          System.arraycopy(output, 0, rv, 0, rv.length);
//        }
//
//        Arrays.fill(output, (byte) 0);
//
//        return rv;
//      }
//    }
//
//    private static java.security.KeyPair generateRSAKeyPair () throws Exception {
//      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
//      keyGen.initialize(2048);
//      return keyGen.generateKeyPair();
//    }
//
//    private static byte[] prepareMessage (String message){
//      byte paddingByte = (byte) 0xAB; // 1010 1011 in binary
//      byte[] messageBytes = message.getBytes();
//      byte[] paddedMessage = new byte[255];
//      paddedMessage[0] = paddingByte;
//      System.arraycopy(messageBytes, 0, paddedMessage, 1, messageBytes.length);
//      return paddedMessage;
//    }
//
//    private static boolean isPaddingCorrect ( byte[] data){
//      byte expectedPaddingByte = (byte) 0xAB; // 1010 1011 in binary
//      return data[0] == expectedPaddingByte;
//    }


  }
