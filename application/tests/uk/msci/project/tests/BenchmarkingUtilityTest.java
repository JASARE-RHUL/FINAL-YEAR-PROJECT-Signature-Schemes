package uk.msci.project.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

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

  @Test
  void testStopTimer() {
    benchmarkingUtility.startTimer();
    try {
      Thread.sleep(10); // Simulate a delay
    } catch (InterruptedException e) {
      e.printStackTrace();
    }
    benchmarkingUtility.stopTimer();
    long duration = benchmarkingUtility.getComputationTimes()
        .get(benchmarkingUtility.getComputationTimes().size() - 1);
    assertTrue(duration > 0, "Computation time should be greater than zero after stopping timer.");
  }

  @Test
  void testGetLastComputationTime() {
    benchmarkingUtility.startTimer();
    try {
      Thread.sleep(10); // Simulate a delay
    } catch (InterruptedException e) {
      e.printStackTrace();
    }
    benchmarkingUtility.stopTimer();
    long lastTime = benchmarkingUtility.getLastComputationTime();
    assertTrue(lastTime > 0, "The last computation time should be greater than zero.");
  }

  @Test
  void testGetComputationTimes() {
    benchmarkingUtility.startTimer();
    benchmarkingUtility.stopTimer();
    assertEquals(1, benchmarkingUtility.getComputationTimes().size(),
        "There should be one computation time recorded.");
  }



}
