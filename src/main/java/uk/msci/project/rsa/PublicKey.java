package uk.msci.project.rsa;

import java.math.BigInteger;

public class PublicKey extends Key {

  public PublicKey(BigInteger exponent) {
    super(exponent);
  }
}
