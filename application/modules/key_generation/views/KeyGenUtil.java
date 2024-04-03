package uk.msci.project.rsa;

public class KeyGenUtil {
  public static int[] convertStringToIntArray (String s) {

    String[] numberStrings = s.split("\\s*,\\s*");
    int[] intArray = new int[numberStrings.length];
    int k = numberStrings.length;
    for (int i = 0; i < k; i++) {
      // if number is too big to parse as Integer
      // pass, use a bit size larger than the maximum bit size
      // to cause the process to fail
      try {
        intArray[i] = Integer.parseInt(numberStrings[i]);
      } catch (NumberFormatException e) {
        intArray[i] = 8000;
      }
    }
    return intArray;

  }

}
