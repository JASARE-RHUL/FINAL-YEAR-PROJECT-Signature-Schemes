package uk.msci.project.rsa;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.apache.commons.math3.distribution.NormalDistribution;
import org.apache.commons.math3.distribution.TDistribution;
import org.apache.commons.math3.stat.descriptive.DescriptiveStatistics;


/**
 * This class provides helper methods for facilitating statistical analysis of time measurements.
 */
public class BenchmarkingUtility {

  /**
   * Calculates the arithmetic mean of the provided times.
   *
   * @param times the list of times to calculate the mean for.
   * @return the mean value.
   */
  public static double calculateMean(List<Long> times) {
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
  public static double calculateMedian(List<Long> times) {
    if (times.isEmpty()) {
      return 0;
    }
    List<Long> sortedTimes = new ArrayList<>(times);
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
  public static long calculateRange(List<Long> times) {
    if (times.isEmpty()) {
      return 0;
    }
    return getMax(times) - getMin(times);
  }

  /**
   * Calculates the given percentile of the provided times.
   *
   * @param times      the list of times to calculate the percentile for.
   * @param percentile the percentile to calculate (e.g., 25 for the 25th percentile).
   * @return the value at the given percentile.
   */
  public static double calculatePercentile(List<Long> times, double percentile) {
    DescriptiveStatistics stats = new DescriptiveStatistics();
    for (long time : times) {
      stats.addValue(time);
    }
    // Multiply by 100 because getPercentile expects a value between 0 and 100
    return stats.getPercentile(percentile * 100);
  }

  /**
   * Calculates the standard deviation of the provided times.
   *
   * @param times the list of times to calculate the standard deviation for.
   * @return the standard deviation value.
   */
  public static double calculateStandardDeviation(List<Long> times) {
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
  public static double calculateVariance(List<Long> times) {
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
  public static long getMin(List<Long> times) {
    return Collections.min(times);
  }

  /**
   * Finds the maximum time in the provided list.
   *
   * @param times the list of times to find the maximum from.
   * @return the maximum time value.
   */
  public static long getMax(List<Long> times) {
    return Collections.max(times);
  }

  /**
   * Calculates the confidence interval for the mean of the given times.
   *
   * @param times           The list of times.
   * @param confidenceLevel The confidence level (e.g., 0.95 for 95% confidence).
   * @return An array containing the lower and upper bounds of the confidence interval.
   */
  public static double[] calculateConfidenceInterval(List<Long> times, double confidenceLevel) {
    double mean = calculateMean(times);
    double standardDeviation = calculateStandardDeviation(times);
    int n = times.size();

    double criticalValue;
    if (n > 30) {
      // Use the normal distribution for large sample sizes
      NormalDistribution normalDistribution = new NormalDistribution();
      criticalValue = normalDistribution.inverseCumulativeProbability(
          1.0 - (1 - confidenceLevel) / 2);
    } else {
      // Use the t-distribution for small sample sizes
      TDistribution tDistribution = new TDistribution(n - 1);
      criticalValue = tDistribution.inverseCumulativeProbability(1.0 - (1 - confidenceLevel) / 2);
    }

    double marginOfError = criticalValue * standardDeviation / Math.sqrt(n);
    return new double[]{mean - marginOfError, mean + marginOfError};
  }

  /**
   * Calculates the total sum of the provided times.
   *
   * @param times the list of times to calculate the sum for.
   * @return the total sum value.
   */
  public static long calculateSum(List<Long> times) {
    long sum = 0;
    for (Long time : times) {
      sum += time;
    }
    return sum;
  }

}
