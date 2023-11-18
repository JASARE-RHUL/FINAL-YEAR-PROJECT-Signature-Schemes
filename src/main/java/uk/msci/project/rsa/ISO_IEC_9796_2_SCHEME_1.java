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
   * Maximum allowed bytes for message portion of encoded message.J Java Implemntation detail
   * requires subtraction of an extra byte due to the prepending of 0x00 byte to encoded message
   */
  int availableSpace = emLen - hashSize - 3;


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
    m1Len = M.length;

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


  /**
   * Verifies an RSA signature according to the ISO/IEC 9796-2 Scheme 1 standard. Validates the
   * encoded message structure, recovers the message, and checks the hash.
   *
   * @param m2 The non-recoverable part of the message (m2).
   * @param S  The signature to be verified.
   * @return A SignatureRecovery object containing the result of the verification and any recovered
   * message.
   * @throws DataFormatException if the signature format is not valid.
   */
  public SignatureRecovery verifyMessageISO(byte[] m2, byte[] S) throws DataFormatException {
    BigInteger s = OS2IP(S);
    BigInteger m = s.modPow(exponent, modulus);
    byte[] EM = I2OSP(m);

    // Check the padding
    if (!(EM[1] == (PADLFIRSTNIBBLE |= (PADLSECONDNIBBLE & 0x0F)) && (EM[this.emLen - 1]
        == PADR))) {

      return new SignatureRecovery(false, null,
          this.getClass());
    }
    byte[] EMHash = Arrays.copyOfRange(EM, EM.length - hashSize - 1, EM.length - 1);

    byte[] m1 = recoverM1FromEM(EM);

    md.update(m1);
    addM2(m2);
    byte[] m1m2Hash = md.digest();
    // Compare the computed hash with the extracted hash from EM
    boolean hashMatch = Arrays.equals(EMHash, m1m2Hash);

    // Return a new SignatureRecovery object with the result of the verification and recovered message
    return new SignatureRecovery(hashMatch, hashMatch ? m1 : null, this.getClass());
  }

  /**
   * Gets the recoverable part of message of a previously signed message from its corresponding
   * encoded message EM. This method is part of signature verification process.
   *
   * @param EM The encoded message from which M1 is to be recovered. It is a byte array that
   *           contains the encoded form of the message as per the RSA signature scheme.
   * @return A byte array representing the recovered message part M1. It is extracted from the
   * encoded message EM and trimmed of any trailing zeros.
   */
  private byte[] recoverM1FromEM(byte[] EM) {
    int hashStartIndex = emLen - 1 - hashSize;
    // Calculate the length of m1
    int m1Length = hashStartIndex - 3;
    byte[] m1Candidate = new byte[m1Length];

    // Start copying from the third byte of EM, as first two bytes are padding
    System.arraycopy(EM, 2, m1Candidate, 0, m1Length);

    // Trim potential trailing zeros from m1
    int m1EndIndex = m1Candidate.length;
    while (m1EndIndex > 0 && m1Candidate[m1EndIndex - 1] == 0) {
      m1EndIndex--;
    }

    return Arrays.copyOfRange(m1Candidate, 0, m1EndIndex);
  }

  /**
   * Processes and adds the non-recoverable part of the message (m2) to the message digest. This is
   * part of the message that is not covered by the signature.
   *
   * @param m2 The non-recoverable part of the message (m2).
   */
  public abstract void addM2(byte[] m2);


}
