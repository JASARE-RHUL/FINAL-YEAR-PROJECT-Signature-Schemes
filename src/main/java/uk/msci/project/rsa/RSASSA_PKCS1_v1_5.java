package uk.msci.project.rsa;

import java.util.Arrays;
import java.util.zip.DataFormatException;

/**
 * This class implements the RSASSA-PKCS1-v1_5 signature scheme using RSA keys. It provides
 * functionalities to sign and verify messages with RSA digital signatures, conforming to the PKCS#1
 * v1.5 specification.
 */
public class RSASSA_PKCS1_v1_5 {

  /**
   * The RSA key containing the exponent and modulus.
   */
  private final Key key;


  /**
   * Constructs an RSASSA_PKCS1_v1_5 instance with the specified RSA key. Initialises the modulus
   * and exponent from the key, calculates the encoded message length, and sets up the SHA-256
   * message digest along with a predefined hash ID.
   *
   * @param key The RSA key containing the exponent and modulus.
   */
  public RSASSA_PKCS1_v1_5(Key key) {
    this.key = key;
  }


  public byte[] EMSA_PKCS1_v1_5_ENCODE(byte[] M) throws DataFormatException {

    int emBits = this.key.getModulus().bitLength() - 1;
    int emLen = (emBits + 7) / 8;

    // Prepare padding string PS consisting of padding bytes (0xFF).
    int psLength =
        emLen - M.length - 3; // Subtracting the prefix (0x00 || 0x01) and postfix (0x00) lengths
    byte[] PS = new byte[psLength];
    Arrays.fill(PS, (byte) 0xFF);

    // Concatenate PS, the DigestInfo, and other padding to form the encoded message EM.
    byte[] EM = new byte[emLen];
    int offset = 0;
    EM[offset++] = 0x00; // Initial 0x00
    EM[offset++] = 0x01; // Block type 0x01 for PKCS signatures
    System.arraycopy(PS, 0, EM, offset, psLength); // Padding
    offset += psLength;
    EM[offset++] = 0x00; // Separator
    System.arraycopy(M, 0, EM, offset, M.length);

    return EM;
  }
}





