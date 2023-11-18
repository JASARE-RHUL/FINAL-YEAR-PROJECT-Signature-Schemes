package uk.msci.project.rsa;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.zip.DataFormatException;

/**
 * This abstract class implements the ISO/IEC 9796-2 Scheme 1 signature scheme using RSA keys. It
 * provides functionalities for signing and verifying messages with RSA digital signatures,
 * conforming to the ISO/IEC 9796-2:2010 specification.
 */
public abstract class ISO_IEC_9796_2_SCHEME_1 extends SigScheme {

  /**
   * Length of the non-recoverable part of the message (m2).
   */
  int m2Len;

  /**
   * Length of the recoverable part of the message (m1).
   */
  int m1Len;


  /**
   * Second nibble of Left padding byte in the encoded message.
   */
  final byte PADLSECONDNIBBLE = (byte) 0x0A;

  /**
   * First nibble of Left padding byte in the encoded message.
   */
  byte PADLFIRSTNIBBLE;


  /**
   * Right padding byte in the encoded message, fixed to 0xBC.
   */
  final byte PADR = (byte) 0xBC;

  /**
   * Size of the SHA-256 hash used in the encoding process, set to 32 bytes (256 bits).
   */
  final int hashSize = 32;


  /**
   * Constructs an instance of ISO_IEC_9796_2_SCHEME_1 with the specified RSA key and left padding
   * byte.
   *
   * @param key             The RSA key containing the modulus and exponent.
   * @param PADLFIRSTNIBBLE The first nibble of the left padding byte to be used in the encoded
   *                        message.
   */
  public ISO_IEC_9796_2_SCHEME_1(Key key, byte PADLFIRSTNIBBLE) {
    super(key);
    this.PADLFIRSTNIBBLE = PADLFIRSTNIBBLE;
  }

  /**
   * Encodes a message following the ISO/IEC 9796-2:2010 standard, which includes hashing the
   * message and preparing the encoded message with specified padding. The format of the encoded
   * message is: Partial Recovery: 0x6A ∥ m1 ∥ hash ∥ 0xBC. Full Recovery: 0x4A ∥ m ∥ hash ∥ 0xBC.
   * Java equivalent format requires prepending of 0x00 byte.
   *
   * @param M The message to be encoded.
   * @return The encoded message as a byte array.
   */
  public byte[] encodeMessage(byte[] M) throws DataFormatException {

    byte[] EM = new byte[emLen];
    int offset = 0;

    EM[offset++] = 0x00; // Initially zero
    // Initialize with PADLFIRSTNIBBLE and PADLSECONDNIBBLE to make 0x6A
    EM[offset] = PADLFIRSTNIBBLE; // Set high nibble to 0110
    EM[offset++] |= (PADLSECONDNIBBLE & 0x0F); // Set low nibble to 1010

    // Calculate available space for the message
    int availableSpace = emLen - hashSize - 3; // -1 for final padding byte
    m1Len = M.length;
    m2Len = Math.max(0, m1Len - availableSpace);

    int messageLength = Math.min(m1Len, availableSpace);
    byte[] m1 = new byte[messageLength];
    System.arraycopy(M, 0, m1, 0, messageLength);
    System.arraycopy(m1, 0, EM, offset, messageLength);
    offset += messageLength;

    // Pad with zeros if m_r (m1) is shorter than the available space
    offset += (availableSpace - messageLength);

    byte[] hashedM = hashM1(M, m1);
    System.arraycopy(hashedM, 0, EM, offset, hashSize);
    offset += hashSize;
    EM[offset] = PADR;

    return EM;
  }

  /**
   * Generates a corresponding hash of the recoverable part of specified message according to the
   * mode of recovery of the currently instantiated ISO_IEC_9796_2_SCHEME_1 instance.
   *
   * @param M  The full message.
   * @param M1 The recoverable part of the message.
   * @return A byte array representing the hash of M1 and M.
   */
  public abstract byte[] hashM1(byte[] M, byte[] M1);



}
