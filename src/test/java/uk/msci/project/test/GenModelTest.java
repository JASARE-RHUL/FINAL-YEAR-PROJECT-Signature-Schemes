package uk.msci.project.test;

import static org.junit.Assert.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.msci.project.rsa.GenModel;
import uk.msci.project.rsa.GenRSA;
import uk.msci.project.rsa.ISO_IEC_9796_2_SCHEME_1;
import uk.msci.project.rsa.Key;
import uk.msci.project.rsa.KeyPair;
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

  @Test
  public void testSetKeyParameters() throws IllegalAccessException, NoSuchFieldException {
    int k = 3; // Example value
    int[] lambda = {512, 256, 256}; // Example bit sizes
    genModel.setKeyParameters(k, lambda);

    Field actualK = GenModel.class.getDeclaredField("k");
    actualK.setAccessible(true);
    int kVal = (int) actualK.get(genModel);

    Field actualLambda = GenModel.class.getDeclaredField("lambda");
    actualLambda.setAccessible(true);
    int[] actualLambdaVal = (int[]) actualLambda.get(genModel);
    assertArrayEquals(lambda, actualLambdaVal);
    assertEquals(k, kVal);
  }

  @Test
  public void testGenerateKeyWithParameters() throws NoSuchFieldException, IllegalAccessException {
    int k = 2;
    int[] lambda = {512, 512};
    genModel.setKeyParameters(k, lambda);
    genModel.setGen();

    Field currentGen = GenModel.class.getDeclaredField("currentGen");
    currentGen.setAccessible(true);
    GenRSA currentGenVal = (GenRSA) currentGen.get(genModel);
    assertNotNull(currentGenVal);

    Field actualK = GenModel.class.getDeclaredField("k");
    actualK.setAccessible(true);
    int kVal = (int) actualK.get(genModel);

    Field actualLambda = GenModel.class.getDeclaredField("lambda");
    actualLambda.setAccessible(true);
    int[] actualLambdaVal = (int[]) actualLambda.get(genModel);

    assertArrayEquals(lambda, actualLambdaVal);
    assertEquals(k, kVal);

  }

}

