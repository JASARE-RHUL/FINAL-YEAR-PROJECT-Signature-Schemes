package uk.msci.project.test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.msci.project.rsa.Key;
import uk.msci.project.rsa.PrivateKey;


public class PrivateKeyTest {


  static void deleteFilesWithSuffix(String fileNamePrefix, String fileExtension) {
    // Use the current working directory as the default directory path
    String directoryPath = ".";
    File directory = new File(directoryPath);

    // Check if the directory exists and is actually a directory
    if (!directory.exists() || !directory.isDirectory()) {
      System.out.println("Provided path is not a valid directory");
      return;
    }
    File keyFile = new File(System.getProperty("user.dir"), "key.rsa");
    keyFile.delete();
    // List all files in the directory
    File[] files = directory.listFiles();

    if (files != null && files.length > 0) {
      for (File file : files) {
        String fileName = file.getName();

        // Check if the file name matches the specified pattern
        if (fileName.matches(fileNamePrefix + "_\\d+\\." + fileExtension) || fileName.
        matches(fileNamePrefix + fileExtension)) {
          // Attempt to delete the file and print the result
          if (file.delete()) {
            System.out.println("Deleted: " + fileName);
          } else {
            System.out.println("Failed to delete: " + fileName);
          }
        }
      }
    } else {
      System.out.println("No files found in the specified directory");
    }
  }

  @BeforeEach
  // Before each test is run, clear any created key files.
  public void setup() {
    String fileNamePrefix = "key";
    String fileExtension = "rsa";
    deleteFilesWithSuffix(fileNamePrefix, fileExtension);
  }



  @Test
    // Test 1
    // Create a field representing the exponent of the key
    // and a method (getter) that returns the value of the field
  void testGetExponent() {
    BigInteger expectedExponent = new BigInteger("98765432109876543210");
    Key privateKey = new PrivateKey(new BigInteger("776545678988777"),
        new BigInteger("98765432109876543210"));

    BigInteger actualExponent = privateKey.getExponent();

    // Assert
    assertEquals(expectedExponent, actualExponent,
        "The getExponent method should return the correct exponent value");
  }

  @Test
    // Test 2
    // Create a field representing the modulus of the key
    // and a method (getter) that returns the value of the field
  void testGetModulus() {
    BigInteger expectedN = new BigInteger("7645433344443333");
    Key privateKey = new PrivateKey(new BigInteger("7645433344443333"),
        new BigInteger("43456564545554"));

    BigInteger actualN = privateKey.getModulus();

    // Assert
    assertEquals(expectedN, actualN,
        "The getModulus method should return the correct Modulus value");
  }

  @Test
    // Test 3
    // Test that setting any component of key to negative/null value throws an appropriate exception
  void testNegativeKeyValue() {

    // Define some test cases
    BigInteger[] modulusTestCases = {
        new BigInteger("12345678901234567890"),
        BigInteger.ZERO,
        new BigInteger("-12345678901234567890")
    };

    BigInteger[] exponentTestCases = {
        new BigInteger("98765432109876543210"),
        BigInteger.ZERO,
        new BigInteger("-98765432109876543210")
    };

    // Positive case - both modulus and exponent are positive
    assertDoesNotThrow(() -> new PrivateKey(modulusTestCases[0], exponentTestCases[0]),
        "privateKey should accept positive modulus and exponent");

    // Edge case - modulus or exponent is zero
    assertThrows(IllegalArgumentException.class,
        () -> new PrivateKey(modulusTestCases[1], exponentTestCases[0]),
        "privateKey should not accept modulus equal to zero");

    assertThrows(IllegalArgumentException.class,
        () -> new PrivateKey(modulusTestCases[0], exponentTestCases[1]),
        "privateKey should not accept exponent equal to zero");

    // Negative case - modulus or exponent is negative
    assertThrows(IllegalArgumentException.class,
        () -> new PrivateKey(modulusTestCases[2], exponentTestCases[0]),
        "privateKey should not accept negative modulus");

    assertThrows(IllegalArgumentException.class,
        () -> new PrivateKey(modulusTestCases[0], exponentTestCases[2]),
        "privateKey should not accept negative exponent");

    // Test for null values
    assertThrows(NullPointerException.class, () -> new PrivateKey(null, exponentTestCases[0]),
        "privateKey should not accept null modulus");

    assertThrows(NullPointerException.class, () -> new PrivateKey(null, null),
        "privateKey should not accept null modulus");

    assertThrows(NullPointerException.class, () -> new PrivateKey(modulusTestCases[0], null),
        "privateKey should not accept null exponent");

  }

  @Test
  // Test 4
  // Create a constructor that enables a key to be parsed from a string input
  // Test that the key can be constructed with a valid key input of a comma
  // seperated modulus and exponent
  public void testKeyWithStringValidInput() {
    String input = "23456788,897654";
    Key key = new PrivateKey(input);

    assertEquals(new BigInteger("23456788"), key.getModulus(),
        "Modulus should be correctly parsed and set");
    assertEquals(new BigInteger("897654"), key.getExponent(),
        "Exponent should be correctly parsed and set");

  }

  @Test
  // Test 5
  // Test that the key cannot be constructed with an incorrectly formatted String representation
  public void testKeyWithStringInvalidDelimiter() {
    String input = "123456789;987654321";
    assertThrows(IllegalArgumentException.class, () -> new PrivateKey(input),
        "Should throw an exception when the wrong delimiter e.g., not a comma is used");
  }

  @Test
  // Test 6
  // Test that the key cannot be constructed with an incorrectly formatted String
  // representation in the general case ,rather than on an ad hoc basis as in test 6
  public void testKeyWithStringFormat() {
    String input = "123456789,";
    assertThrows(IllegalArgumentException.class, () -> new PrivateKey(input),
        "Should throw an exception for missing values");
    assertThrows(NullPointerException.class, () -> new PrivateKey((String) null),
        "Should throw an exception for null input");

    String nonNumber = "notANumber,987654321";
    assertThrows(IllegalArgumentException.class, () -> new PrivateKey(nonNumber),
        "Should throw an exception for non-numeric input");
  }

  @Test
    // Test 7
    // Create a getter for when the field corresponding to a full key representation is initialised
    // Test that the getter for key value correctly returns the initialised key value
  void testGetKeyValue() {
    String input = "76545679087,56834434789";
    Key privateKey = new PrivateKey(input);
    String actualValue = privateKey.getKeyValue();
    // Assert
    assertEquals(input, actualValue,
        "The getKeyValue method should return the correct key value");
  }

  @Test
    // Test 8
    // Create a method exportToFile, that enables key value to be saved to a users file system.
    // Test that the key value is successfully saved by check for existence of file and
    // checking equality between the input string and string read in from file
  void testKeyExport() throws IOException {
    String input = "4567890876465,234567890786";
    Key privateKey = new PrivateKey(input);
    String actualValue = privateKey.getKeyValue();
    privateKey.exportToFile("key.rsa");

    File file = new File("key.rsa");
    assertTrue(file.exists());
    StringBuilder content = new StringBuilder();

    try (FileInputStream fis = new FileInputStream(file);
        InputStreamReader isr = new InputStreamReader(fis, StandardCharsets.UTF_8);
        BufferedReader br = new BufferedReader(isr)) {
      String line;
      while ((line = br.readLine()) != null) {
        content.append(line);
      }
    }
    assertEquals(input, content.toString());

  }

  @Test
    // Test 9
    // Create a method exportToFile, that enables key value to be saved to a users file system.
    // Test that the key value is successfully saved by check for existence of file and
    // checking equality between the input string and string read in from file
  void testKeyImport() throws IOException {
    String input = "4567890876465,234567890786";
    Key privateKey = new PrivateKey(input);

    privateKey.exportToFile("key.rsa");

    File file = new File("key.rsa");
    assertTrue(file.exists());
    StringBuilder content = new StringBuilder();

    try (FileInputStream fis = new FileInputStream(file);
        InputStreamReader isr = new InputStreamReader(fis, StandardCharsets.UTF_8);
        BufferedReader br = new BufferedReader(isr)) {
      String line;
      while ((line = br.readLine()) != null) {
        content.append(line);
      }
    }
    assertEquals(input, content.toString());

  }

  @Test
    // Test 10
    // Enable the exportToFile method to handle a file with same name already existing
  void testKeyFileExists() throws IOException {
    String input = "778987654345,23456789";
    Key privateKey = new PrivateKey(input);

    privateKey.exportToFile("key.rsa");
    privateKey.exportToFile("key.rsa");
    File file_1 = new File(System.getProperty("user.dir"), "key.rsa");
    File file_2 = new File(System.getProperty("user.dir"), "Key_1.rsa");
    assertTrue(file_1.exists());
    assertTrue(file_2.exists());

  }

  @Test
    // Test 11
    // "Create a constructor that enables a key to be parsed from an imported file"
  void testImportKey() throws IOException {
    String input = "5644783998877,4567845443";
    Key privateKey = new PrivateKey(input);
    privateKey.exportToFile("key.rsa");
    File keyFile = new File(System.getProperty("user.dir"), "key.rsa");
    Key privateKey_2 = new PrivateKey(keyFile);
    assertEquals(privateKey_2.getKeyValue(), input);




  }

}

