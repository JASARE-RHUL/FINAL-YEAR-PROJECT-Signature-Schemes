package uk.msci.project.rsa;

import java.util.ArrayList;
import java.util.Collections;
import org.apache.commons.math3.distribution.TDistribution;

/**
 * This utility class provides methods to perform benchmarking by recording computation times and
 * calculating various statistical measures.
 */
public class BenchmarkingUtility {

  /**
   * List to store computation times for benchmarking.
   */
  private ArrayList<Long> computationTimes;

  /**
   * Constructs a new BenchmarkingUtility instance.
   */
  public BenchmarkingUtility() {
    this.computationTimes = new ArrayList<>();
  }

  /**
   * Starts the timer for a computation by recording the current time.
   */
  public void startTimer() {
    computationTimes.add(System.nanoTime());
  }

  /**
   * Retrieves the list of recorded computation times.
   *
   * @return an ArrayList of recorded computation times.
   */
  public ArrayList<Long> getComputationTimes() {
    return computationTimes;
  }

  /**
   * Stops the timer for the last computation and records its duration.
   */
  public void stopTimer() {
    int lastIndex = computationTimes.size() - 1;
    long startTime = computationTimes.get(lastIndex);
    long endTime = System.nanoTime();
    computationTimes.set(lastIndex, endTime - startTime);
  }

  /**
   * Retrieves the last recorded computation time.
   *
   * @return the duration of the last computation in nanoseconds, or 0 if no computations have been
   * recorded.
   */
  public long getLastComputationTime() {
    if (!computationTimes.isEmpty()) {
      return computationTimes.get(computationTimes.size() - 1);
    }
    return 0;
  }

  // The following methods all include generalised forms to take an ArrayList<Long> as input.
  // This allows the methods to be reusable for different sets of time data.

  /**
   * Calculates the arithmetic mean of the provided times.
   *
   * @param times the list of times to calculate the mean for.
   * @return the mean value.
   */
  public static double calculateMean(ArrayList<Long> times) {
    if (times.isEmpty()) {
      return 0;
    }
    long sum = 0;
    for (Long time : times) {
      sum += time;
    }
    return sum / (double) times.size();
  }

  /**
   * Calculates the median of the provided times.
   *
   * @param times the list of times to calculate the median for.
   * @return the median value.
   */
  public static double calculateMedian(ArrayList<Long> times) {
    if (times.isEmpty()) {
      return 0;
    }
    ArrayList<Long> sortedTimes = new ArrayList<>(times);
    Collections.sort(sortedTimes);
    int middle = sortedTimes.size() / 2;
    if (sortedTimes.size() % 2 == 0) {
      return (sortedTimes.get(middle - 1) + sortedTimes.get(middle)) / 2.0;
    } else {
      return sortedTimes.get(middle);
    }
  }

  /**
   * Calculates the range (max - min) of the provided times.
   *
   * @param times the list of times to calculate the range for.
   * @return the range value.
   */
  public static long calculateRange(ArrayList<Long> times) {
    if (times.isEmpty()) {
      return 0;
    }
    long min = Collections.min(times);
    long max = Collections.max(times);
    return max - min;
  }

  /**
   * Calculates the given percentile of the provided times.
   *
   * @param times      the list of times to calculate the percentile for.
   * @param percentile the percentile to calculate (e.g., 25 for the 25th percentile).
   * @return the value at the given percentile.
   */
  public static double calculatePercentile(ArrayList<Long> times, double percentile) {
    if (times.isEmpty()) {
      return 0;
    }
    ArrayList<Long> sortedTimes = new ArrayList<>(times);
    Collections.sort(sortedTimes);
    int index = (int) Math.ceil(percentile / 100.0 * sortedTimes.size()) - 1;
    return sortedTimes.get(Math.max(index, 0));
  }

  /**
   * Calculates the standard deviation of the provided times.
   *
   * @param times the list of times to calculate the standard deviation for.
   * @return the standard deviation value.
   */
  public static double calculateStandardDeviation(ArrayList<Long> times) {
    double mean = calculateMean(times);
    double temp = 0;
    for (long time : times) {
      temp += (time - mean) * (time - mean);
    }
    return Math.sqrt(temp / times.size());
  }

  /**
   * Calculates the variance of the provided times.
   *
   * @param times the list of times to calculate the variance for.
   * @return the variance value.
   */
  public static double calculateVariance(ArrayList<Long> times) {
    double mean = calculateMean(times);
    double temp = 0;
    for (long time : times) {
      temp += (time - mean) * (time - mean);
    }
    return temp / times.size();
  }
  /**
   * Finds the minimum time in the provided list.
   *
   * @param times the list of times to find the minimum from.
   * @return the minimum time value.
   */
  public static long getMin(ArrayList<Long> times) {
    return Collections.min(times);
  }

  /**
   * Finds the maximum time in the provided list.
   *
   * @param times the list of times to find the maximum from.
   * @return the maximum time value.
   */
  public static long getMax(ArrayList<Long> times) {
    return Collections.max(times);
  }

  /**
   * Calculates the confidence interval for the mean of the given times.
   *
   * @param times           The list of times.
   * @param confidenceLevel The confidence level (e.g., 0.95 for 95% confidence).
   * @return An array containing the lower and upper bounds of the confidence interval.
   */
  public double[] calculateConfidenceInterval(ArrayList<Long> times, double confidenceLevel) {
    double mean = calculateMean(times);
    double standardDeviation = calculateStandardDeviation(times);
    int n = times.size();


    TDistribution tDistribution = new TDistribution(n - 1);
    double criticalValue = tDistribution.inverseCumulativeProbability(1.0 - (1 - confidenceLevel) / 2);


    double marginOfError = criticalValue * standardDeviation / Math.sqrt(n);
    return new double[]{mean - marginOfError, mean + marginOfError};
  }




}
