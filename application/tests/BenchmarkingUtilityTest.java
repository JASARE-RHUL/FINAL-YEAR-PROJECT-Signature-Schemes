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
  void testCalculateMean() {
    double actualMean = BenchmarkingUtility.calculateMean(exampleTimes);
    double expectedMean = 300.0;
    assertEquals(expectedMean, actualMean, "The mean should be calculated " +
      "correctly.");
  }

  @Test
  void testCalculateMedian() {
    double actualMedian = BenchmarkingUtility.calculateMedian(exampleTimes);
    double expectedMedian = 300.0;
    assertEquals(expectedMedian, actualMedian, "The median should be " +
      "calculated correctly.");
  }

  @Test
  void testCalculateRange() {
    long actualRange = BenchmarkingUtility.calculateRange(exampleTimes);
    long expectedRange = 400L;
    assertEquals(expectedRange, actualRange, "The range should be calculated " +
      "correctly.");
  }

  @Test
  void testCalculatePercentile() {
    double actual25th = BenchmarkingUtility.calculatePercentile(exampleTimes,
      0.25);
    double actual75th = BenchmarkingUtility.calculatePercentile(exampleTimes,
      0.75);
    assertEquals(150.0, actual25th, "The 25th percentile should be calculated" +
      " correctly.");
    assertEquals(450.0, actual75th, "The 75th percentile should be calculated" +
      " correctly.");
  }

  @Test
  void testCalculateStandardDeviation() {
    double actualStdDev =
      BenchmarkingUtility.calculateStandardDeviation(exampleTimes);
    double expectedStdDev = Math.sqrt(20000.0);
    assertEquals(expectedStdDev, actualStdDev, "The standard deviation should" +
      " be calculated correctly.");
  }

  @Test
  void testCalculateVariance() {
    double actualVariance = BenchmarkingUtility.calculateVariance(exampleTimes);
    double expectedVariance = 20000.0;
    assertEquals(expectedVariance, actualVariance, "The variance should be " +
      "calculated correctly.");
  }

  @Test
  void testGetMin() {
    long actualMin = BenchmarkingUtility.getMin(exampleTimes);
    assertEquals(100L, actualMin, "The minimum value should be found " +
      "correctly.");
  }

  @Test
  void testGetMax() {
    long actualMax = BenchmarkingUtility.getMax(exampleTimes);
    assertEquals(500L, actualMax, "The maximum value should be found " +
      "correctly.");
  }

  @Test
  public void testConfidenceIntervalSmallSample() {
    BenchmarkingUtility benchmarkingUtility = new BenchmarkingUtility();
    ArrayList<Long> times = new ArrayList<>();

    times.add(100L);
    times.add(200L);
    times.add(150L);

    double confidenceLevel = 0.95;
    double[] confidenceInterval =
      benchmarkingUtility.calculateConfidenceInterval(times, confidenceLevel);

    assertTrue(confidenceInterval[0] < confidenceInterval[1]);
  }

  @Test
  public void testConfidenceIntervalLargeSample() {
    BenchmarkingUtility benchmarkingUtility = new BenchmarkingUtility();
    ArrayList<Long> times = new ArrayList<>();
    // Add sample data (large sample size, e.g., > 30)
    for (int i = 0; i < 50; i++) {
      times.add(100L + i);
    }
    double confidenceLevel = 0.95;
    double[] confidenceInterval =
      benchmarkingUtility.calculateConfidenceInterval(times, confidenceLevel);

    assertTrue(confidenceInterval[0] < confidenceInterval[1]);
  }


}
