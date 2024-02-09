package uk.msci.project.rsa;

import java.util.List;

/**
 * The {@code ResultsModel} class stores and calculates various statistical metrics based on a
 * specified set of results gathered from a benchmarking run for a core digital signature
 * operation.
 */
public class ResultsModel {

  /**
   * A list of time measurements from the benchmarking trials.
   */
  private List<Long> results;

  /**
   * The total number of trials conducted.
   */
  private int numTrials;

  /**
   * The sum of all time measurements.
   */
  private double overallData;

  /**
   * The mean (average) of the time measurements.
   */
  private double meanData;

  /**
   * The confidence interval for the mean with a specified level of confidence.
   */
  private double[] confidenceInterval;

  /**
   * The 25th percentile value of the time measurements.
   */
  private double percentile25Data;

  /**
   * The median (50th percentile) of the time measurements.
   */
  private double medianData;

  /**
   * The 75th percentile value of the time measurements.
   */
  private double percentile75Data;

  /**
   * The range (difference between the maximum and minimum values) of the time measurements.
   */
  private double rangeData;

  /**
   * The standard deviation of the time measurements.
   */
  private double stdDeviationData;

  /**
   * The variance of the time measurements.
   */
  private double varianceData;

  /**
   * The minimum time measurement.
   */
  private double minTimeData;

  /**
   * The maximum time measurement.
   */
  private double maxTimeData;

  /**
   * Constructs a {@code ResultsModel} with a list of time measurements from a benchmarking run.
   *
   * @param results The list of time measurements.
   */
  public ResultsModel(List<Long> results) {
    this.results = results;
  }

  /**
   * Performs the computation of statistical metrics from the collected benchmarking results.
   */
  public void calculateStatistics() {
    this.numTrials = results.size();
    this.overallData = BenchmarkingUtility.calculateSum(this.results) / 1E6;
    this.meanData = BenchmarkingUtility.calculateMean(this.results) / 1E6;
    double[] ci = BenchmarkingUtility.calculateConfidenceInterval(this.results, 0.95);
    this.confidenceInterval = new double[]{
        ci[0] / 1E6,
        ci[1] / 1E6
    };
    this.percentile25Data = BenchmarkingUtility.calculatePercentile(this.results, 0.25) / 1E6;
    this.medianData = BenchmarkingUtility.calculateMedian(this.results) / 1E6;
    this.percentile75Data = BenchmarkingUtility.calculatePercentile(this.results, 0.75) / 1E6;
    this.rangeData =
        (BenchmarkingUtility.getMax(this.results) - BenchmarkingUtility.getMin(this.results))
            / 1E6;
    this.stdDeviationData =
        BenchmarkingUtility.calculateStandardDeviation(this.results) / 1E6;
    this.varianceData = BenchmarkingUtility.calculateVariance(this.results) / (1E6 * 1E6);
    this.minTimeData = BenchmarkingUtility.getMin(this.results) / 1E6;
    this.maxTimeData = BenchmarkingUtility.getMax(this.results) / 1E6;
  }

  /**
   * Returns the number of trials conducted.
   *
   * @return The number of trials.
   */
  public int getNumTrials() {
    return numTrials;
  }

  /**
   * Returns the list of time measurements from the benchmarking trials.
   *
   * @return The list of results.
   */
  public List<Long> getResults() {
    return results;
  }

  /**
   * Returns the overall sum of time measurements.
   *
   * @return The sum of results.
   */
  public double getOverallData() {
    return overallData;
  }

  /**
   * Returns the mean of the time measurements.
   *
   * @return The mean of results.
   */
  public double getMeanData() {
    return meanData;
  }

  /**
   * Returns the confidence interval of the mean.
   *
   * @return An array containing the lower and upper bounds of the confidence interval.
   */
  public double[] getConfidenceInterval() {
    return confidenceInterval;
  }

  /**
   * Returns the 25th percentile of the time measurements.
   *
   * @return The 25th percentile value.
   */
  public double getPercentile25Data() {
    return percentile25Data;
  }

  /**
   * Returns the median of the time measurements.
   *
   * @return The median value.
   */
  public double getMedianData() {
    return medianData;
  }

  /**
   * Returns the 75th percentile of the time measurements.
   *
   * @return The 75th percentile value.
   */
  public double getPercentile75Data() {
    return percentile75Data;
  }

  /**
   * Returns the range of the time measurements.
   *
   * @return The range value.
   */
  public double getRangeData() {
    return rangeData;
  }

  /**
   * Returns the standard deviation of the time measurements.
   *
   * @return The standard deviation value.
   */
  public double getStdDeviationData() {
    return stdDeviationData;
  }

  /**
   * Returns the variance of the time measurements.
   *
   * @return The variance value.
   */
  public double getVarianceData() {
    return varianceData;
  }

  /**
   * Returns the minimum time measurement.
   *
   * @return The minimum time value.
   */
  public double getMinTimeData() {
    return minTimeData;
  }

  /**
   * Returns the maximum time measurement.
   *
   * @return The maximum time value.
   */
  public double getMaxTimeData() {
    return maxTimeData;
  }

}
