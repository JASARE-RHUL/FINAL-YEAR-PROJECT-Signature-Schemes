package uk.msci.project.rsa;

import static java.lang.Math.max;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.zip.DataFormatException;
import uk.msci.project.rsa.exceptions.InvalidDigestException;


/**
 * This class implements the ISO/IEC 9796-2 Scheme 1 signature scheme using RSA keys. It provides
 * functionalities for signing and verifying messages with RSA digital signatures, conforming to the
 * ISO/IEC 9796-2:2010 specification and chooses the appropriate mode of message recovery according
 * to the length of message provided to its sign algorithm.
 */
public class ISO_IEC_9796_2_SCHEME_1 extends SigScheme {

  /**
   * Length of the non-recoverable part of the message (m2).
   */
  int m2Len;

  /**
   * Length of the recoverable part of the message (m1).
   */
  int m1Len;

  /**
   * First nibble of Left padding byte in the encoded message.
   */
  byte PADLFIRSTNIBBLE;


  /**
   * Right padding byte in the encoded message, fixed to 0xBC.
   */
  final byte PADR = (byte) 0xBC;


  /**
   * Indicator of the current mode of recovery
   */
  boolean isFullRecovery;


  /**
   * Constructs an instance of ISO_IEC_9796_2_SCHEME_1 with the specified RSA key
   *
   * @param key The RSA key containing the modulus and exponent.
   */
  public ISO_IEC_9796_2_SCHEME_1(Key key) {
    super(key);
  }

  /**
   * Constructs an instance of ISO_IEC_9796_2_SCHEME_1 with the specified RSA key and a flag for
   * using provably secure parameters. It performs the same initialisations as the single-argument
   * constructor and additionally sets the flag for using provably secure parameters in the
   * signature scheme.
   *
   * @param key                    The RSA key containing the exponent and modulus.
   * @param isProvablySecureParams A boolean flag indicating if provably secure parameters should be
   *                               used in the signature scheme.
   */
  public ISO_IEC_9796_2_SCHEME_1(Key key, boolean isProvablySecureParams) {
    super(key, isProvablySecureParams);
  }

  /**
   * Encodes a message following the ISO/IEC 9796-2:2010 standard (includes hashing the message and
   * preparing the encoded message with specified padding) while also be designed to account for
   * standard or provably secure parameters. The format of the encoded message is: Partial Recovery:
   * 0x6A ∥ m1 ∥ hash ∥ 0xBC. Full Recovery: 0x4B...BA ∥ m ∥ hash ∥ 0xBC.
   * <p>
   * Java equivalent format requires the encoding to be a byte less than the modulus byte size to
   * ensure resulting value is less than modulus.
   *
   * @param M The message to be encoded.
   * @return The encoded message as a byte array.
   */
  @Override
  public byte[] encodeMessage(byte[] M) throws DataFormatException {
    byte[] EM = new byte[emLen];
    m1Len = M.length;
    // available space in bits
    int availableSpace = (hashSize + m1Len) * 8 + 8 + 4 - emBits;
    //Partial recovery if message is larger than available space
    // else scheme proceeds with full recovery.
    if (availableSpace > 0) {
      PADLFIRSTNIBBLE = 0x60;
      isFullRecovery = false;
      availableSpace = ((availableSpace) + 7) / 8;
    } else {
      PADLFIRSTNIBBLE = 0x40;
      isFullRecovery = true;
      availableSpace = -((Math.abs(availableSpace) + 7) / 8);
    }


    int hashStart = emLen - hashSize - 1;
    int delta = hashStart;
    //length of the message to be copied is either the availableSpace most significant bits of
    // M or alternatively the full length of the original message if the message is too short
    int messageLength = Math.min(m1Len, m1Len - availableSpace - 1);
    // m2 comprises the non-recoverable message portion
    m2Len = max(m1Len - messageLength, 0);
    //copying the message
    delta -= messageLength;
    System.arraycopy(M, 0, EM, delta, messageLength);

    // Hash message as normal for standard case, else apply the MGF1 as means for computing hash
    // to generate large hash output (1/2 length of modulus)
    byte[] hashedM = computeHashWithOptionalMasking(M);
    System.arraycopy(hashedM, 0, EM, hashStart, hashSize);

    // Pad with Bs if m_r (m1) is shorter than the available space
    if ((delta - 1) > 0) {
      for (int i = delta - 1; i != 0; i--) {
        EM[i] = (byte) 0xbb;
      }
      // The case of full recovery:
      // modify the second nibble of final PAD_L 0xBB byte to
      // contain 0x0A as per the scheme
      EM[delta - 1] ^= (byte) 0x01;
      EM[0] = (byte) 0x0b;
      EM[0] |= PADLFIRSTNIBBLE;
    } else {
      //The case of partial recovery: no B bytes required
      // So update the second nibble of final and first PAD_L byte
      // to contain 0x0A as per the scheme
      EM[0] = (byte) 0x0a;
      EM[0] |= PADLFIRSTNIBBLE;
    }
    EM[emLen - 1] = PADR;
    return EM;
  }

  /**
   * Creates a signature for specified message and stores the extracted non-recoverable part of the
   * message by initialising its corresponding field in the class
   *
   * @param M The message to be signed.
   * @return A combined byte array containing signature and an appended non-recoverable part of the
   * message.
   * @throws DataFormatException If the message encoding fails.
   */
  @Override
  public byte[] sign(byte[] M) throws DataFormatException {
    byte[] S = super.sign(M);
    // Extract m2 from the original message M using the computed m2's length
    if (m2Len > 0) {
      nonRecoverableM = Arrays.copyOfRange(M, m1Len - m2Len, m1Len);
    }
    return S;
  }

  /**
   * Verifies an RSA signature according to the ISO/IEC 9796-2 Scheme 1 standard. Validates the
   * encoded message structure, allows for implicit message recovery by automatically choosing the
   * mode of recovery based on the length of provided message.
   *
   * @param m2 The non-recoverable part of the message (m2).
   * @param S  The signature to be verified.
   * @return A SignatureRecovery object containing the result of the verification and any recovered
   * message.
   * @throws DataFormatException if the signature format is not valid.
   */
  @Override
  public boolean verifyMessage(byte[] m2, byte[] S) throws DataFormatException {
    BigInteger s = OS2IP(S);
    BigInteger m = RSAVP1(s);
    byte[] EM;
    try {
      EM = I2OSP(m);
    } catch (IllegalArgumentException e) {
      return false;
    }

    // Checks to see that the first two bits are 01 as per the 9796-2 standard
    if (((EM[0] & 0xC0) ^ 0x40) != 0) {
      return false;
    }

    // Checks the recovery mode the signature was created in by checking third bit
    // if third bit is one that indicates full recovery.
    if ((EM[0] & 0x20) == 0 && m2 == null) {
      PADLFIRSTNIBBLE = 0x40;
      isFullRecovery = true;
    } else {
      PADLFIRSTNIBBLE = 0x60;
      isFullRecovery = false;
    }

    if ((EM[emLen - 1] != PADR)) {
      return false;
    }
    int hashStart = emLen - hashSize - 1;
    int mStart = 0;
    //finds the starting index of the recoverable message by checking the first 0x0A nibble
    for (mStart = 0; mStart != emLen; mStart++) {
      if (((EM[mStart] & 0x0f) ^ 0x0a) == 0) {
        break;
      }
    }
    mStart++;

    byte[] EMHash = Arrays.copyOfRange(EM, hashStart, emLen - 1);

    byte[] m1 = Arrays.copyOfRange(EM, mStart, hashStart);

    md.update(m1);

    // Full recovery mode does not have a second message portion
    if (!isFullRecovery) {
      addM2(m2);
    }
    byte[] m1m2Hash = md.digest();
    // Compare the computed hash with the extracted hash from EM
    if (!(Arrays.equals(EMHash, m1m2Hash))) {
      return false;
    }
    recoverableM = m1;
    return true;

  }

  /**
   * Processes and adds the non-recoverable part of the message (m2) to the message digest. This is
   * part of the message that is not covered by the signature.
   *
   * @param m2 The non-recoverable part of the message (m2).
   */
  public void addM2(byte[] m2) {
    if (m2 != null && m2.length > 0) {
      md.update(m2);
    }
  }

  /**
   * Sets the message digest algorithm to be used for hashing in the ISO_IEC_9796_2_SCHEME_1
   * signature scheme to the specified digest type, with the option to specify a custom hash size.
   *
   * @param digestType     The type of message digest algorithm to be set.
   * @param customHashSize The custom hash size, used only for variable-length hash types.
   * @throws NoSuchAlgorithmException If the specified algorithm is not available in the
   *                                  environment.
   * @throws InvalidDigestException   If the specified digest type is invalid or unsupported.
   * @throws NoSuchProviderException  If the specified provider for the algorithm is not available.
   * @throws IllegalArgumentException If the custom hash size is not a positive integer that allows
   *                                  incorporation of minimum padding bytes.
   */
  @Override
  public void setDigest(DigestType digestType, int customHashSize)
      throws NoSuchAlgorithmException, InvalidDigestException, NoSuchProviderException {
    int availableSpace = customHashSize * 8 + 1 + 4 - emBits;
    if (availableSpace > 0) {
      throw new IllegalArgumentException(
          "Custom hash size must a positive integer that allows the minimum bytes of padding to be incorporated");
    }
    super.setDigest(digestType, customHashSize);
  }

  /**
   * Retrieves the hash ID associated with a given digest type. Not applicable to this scheme
   * (ISO_IEC_9796_2_SCHEME_1) where a hash ID is not using in message encoding
   *
   * @param digestType The type of digest algorithm for which the hash ID is required.
   * @return A byte array representing the hash ID associated with the specified digest type.
   * @throws IllegalArgumentException If the provided digest type is not supported.
   */
  @Override
  public byte[] getHashID(DigestType digestType) {
    return new byte[0];
  }


}
