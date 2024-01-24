package uk.msci.project.tests;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.msci.project.rsa.MGF1;
import uk.msci.project.rsa.SignatureModel;

public class MGF1_Test {

  private MGF1 mgf1;


  @BeforeEach
  public void setup() {
    mgf1 = new MGF1();
  }

  @Test
  void testReturnLength() {
    assertEquals(256, mgf1.generateMask(new byte[0], 256).length);

  }

}
