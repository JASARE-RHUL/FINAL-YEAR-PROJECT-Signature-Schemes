package uk.msci.project.tests;

import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.ArrayList;
import java.util.Arrays;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.msci.project.rsa.BenchmarkingUtility;

public class BenchmarkingUtilityTest {
  private BenchmarkingUtility benchmarkingUtility;
  private ArrayList<Long> exampleTimes;

  @BeforeEach
  void setUp() {
    benchmarkingUtility = new BenchmarkingUtility();
    exampleTimes = new ArrayList<>(Arrays.asList(100L, 200L, 300L, 400L, 500L));
  }

  @Test
  void testStartTimer() {
    benchmarkingUtility.startTimer();
    assertFalse(benchmarkingUtility.getComputationTimes().isEmpty(),
        "Computation times list should not be empty after starting timer.");
  }

}
