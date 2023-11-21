package uk.msci.project.test;

import static org.junit.Assert.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.msci.project.rsa.GenModel;
import uk.msci.project.rsa.Key;
import uk.msci.project.rsa.PrivateKey;


public class GenModelTest {

  private GenModel genModel;


  @BeforeEach
  // Before each test is run, clear any created key files.
  public void setup() {
    genModel = new GenModel();

  }

  @Test
  void testInitialization() {
    assertNotNull("GenModel should initialise an object", genModel);
  }

}

