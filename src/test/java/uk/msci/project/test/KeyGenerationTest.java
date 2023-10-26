package uk.msci.project.test;

import java.lang.reflect.Modifier;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import uk.msci.project.rsa.Key;


public class KeyGenerationTest {

  @Test
    // Test 1
    // Create abstract class that provides a foundational representation of an RSA key
    // Test key class to check if it is abstract
  void testGetExponent() {
    Class<Key> key = Key.class;

    Assertions.assertTrue(Modifier.isAbstract(key.getModifiers()));

  }
}
