package uk.msci.project.tests;

import static org.junit.Assert.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import javafx.util.Pair;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.msci.project.rsa.GenModel;
import uk.msci.project.rsa.GenModelComparisonBenchmarking;
import uk.msci.project.rsa.GenRSA;
import uk.msci.project.rsa.KeyPair;


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
    genModel.setGen(false);

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

  @Test
  public void testGenerateKeyValid() throws NoSuchFieldException, IllegalAccessException {
    int k = 3;
    int[] lambda = {1024, 1024, 1024};
    genModel.setKeyParameters(k, lambda);
    genModel.setGen(false);
    genModel.generateKey();
    Field generatedKeyPair = GenModel.class.getDeclaredField("k");
    generatedKeyPair.setAccessible(true);
    KeyPair generatedKeyPairVal = (KeyPair) generatedKeyPair.get(genModel);
    assertNotNull(generatedKeyPairVal);
  }

  @Test
  public void testGenerateKeyNullParam() throws NoSuchFieldException, IllegalAccessException {
    assertThrows(IllegalStateException.class, () -> genModel.generateKey(),
        "Should throw an exception when Key Size is set before a key can be generated");

  }

  @Test
  public void testExport() throws NoSuchFieldException, IllegalAccessException {
    assertThrows(IllegalStateException.class, () -> genModel.generateKey(),
        "Should throw an exception no key has been generated");
  }

  @Test
  public void testFormatCustomKeyConfigurations() {
    GenModelComparisonBenchmarking model = new GenModelComparisonBenchmarking();
    List<Pair<int[], Boolean>> keyConfigurationsData = new ArrayList<>();
    keyConfigurationsData.add(new Pair<>(new int[]{1, 2, 1, 2}, true));
    keyConfigurationsData.add(new Pair<>(new int[]{1, 4, 1, 4, 1, 2}, false));

    List<String> expected = new ArrayList<>();
    expected.add("2 primes (1/2N+1/2N) with small e");
    expected.add("3 primes (1/4N+1/4N+1/2N)");


    List<String> result = model.formatCustomKeyConfigurations(keyConfigurationsData);

    assertEquals(expected, result);
  }



}

