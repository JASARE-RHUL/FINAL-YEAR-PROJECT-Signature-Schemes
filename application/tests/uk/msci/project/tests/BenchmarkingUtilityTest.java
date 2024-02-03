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

  @Test
  void testCalculateMean() {
    double actualMean = BenchmarkingUtility.calculateMean(exampleTimes);
    double expectedMean = 300.0;
    assertEquals(expectedMean, actualMean, "The mean should be calculated correctly.");
  }

  @Test
  void testCalculateMedian() {
    double actualMedian = BenchmarkingUtility.calculateMedian(exampleTimes);
    double expectedMedian = 300.0;
    assertEquals(expectedMedian, actualMedian, "The median should be calculated correctly.");
  }

  @Test
  void testCalculateRange() {
    long actualRange = BenchmarkingUtility.calculateRange(exampleTimes);
    long expectedRange = 400L;
    assertEquals(expectedRange, actualRange, "The range should be calculated correctly.");
  }

  @Test
  void testCalculatePercentile() {
    double actual25th = BenchmarkingUtility.calculatePercentile(exampleTimes, 25);
    double actual75th = BenchmarkingUtility.calculatePercentile(exampleTimes, 75);
    assertEquals(200.0, actual25th, "The 25th percentile should be calculated correctly.");
    assertEquals(400.0, actual75th, "The 75th percentile should be calculated correctly.");
  }

  @Test
  void testCalculateStandardDeviation() {
    double actualStdDev = BenchmarkingUtility.calculateStandardDeviation(exampleTimes);
    double expectedStdDev = Math.sqrt(20000.0);
    assertEquals(expectedStdDev, actualStdDev, "The standard deviation should be calculated correctly.");
  }

  @Test
  void testCalculateVariance() {
    double actualVariance = BenchmarkingUtility.calculateVariance(exampleTimes);
    double expectedVariance = 20000.0;
    assertEquals(expectedVariance, actualVariance, "The variance should be calculated correctly.");
  }


}
