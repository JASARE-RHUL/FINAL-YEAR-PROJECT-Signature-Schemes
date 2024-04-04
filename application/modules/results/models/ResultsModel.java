package uk.msci.project.rsa;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;

import uk.msci.project.rsa.BenchmarkingUtility;
import uk.msci.project.rsa.FileHandle;

/**
 * The {@code ResultsModel} class stores and calculates various statistical
 * metrics based on a
 * specified set of results gathered from a benchmarking run for a core
 * digital signature
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
   * The range (difference between the maximum and minimum values) of the
   * time measurements.
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
   * A  string representing the specific key configuration/parameter type for
   * the key that the
   * benchmarking run relates to.
   */
  private String configString;

  /**
   * The name of the hash function used in the benchmarking run.
   */
  private String hashFunctionName;

  /**
   * The length of the key used in the benchmarking run, measured in bits.
   */
  private int keyLength;

  /**
   * Constructs a {@code ResultsModel} with a list of time measurements from
   * a benchmarking run.
   *
   * @param results The list of time measurements.
   */
  public ResultsModel(List<Long> results) {
    this.results = results;
  }

  /**
   * Constructs a {@code ResultsModel} with a list of time measurements from
   * a benchmarking run,
   * along with additional parameters including the configuration string,
   * hash function name, and
   * key length.
   *
   * @param results          The list of time measurements.
   * @param configString     The specific key configuration used for the key
   *                         benchmarking results
   *                         wer generated based on.
   * @param hashFunctionName The name of the hash function used.
   * @param keyLength        The length of the key used, in bits.
   */
  public ResultsModel(List<Long> results, String configString,
                      String hashFunctionName,
                      int keyLength) {
    this.keyLength = keyLength;
    this.results = results;
    this.configString = configString;
    this.hashFunctionName = hashFunctionName;
  }

  /**
   * Retrieves the key length used in the benchmarking run.
   *
   * @return The key length in bits.
   */
  public int getKeyLength() {
    return keyLength;
  }

  /**
   * Retrieves the configuration string representing the specific key
   * configuration/parameter type
   * for the key that the benchmarking run relates to.
   *
   * @return The configuration string.
   */
  public String getConfigString() {
    return configString;
  }

  /**
   * Retrieves the name of the hash function used in the benchmarking run.
   *
   * @return The hash function name.
   */
  public String getHashFunctionName() {
    return hashFunctionName;
  }

  /**
   * Performs the computation of statistical metrics from the collected
   * benchmarking results.
   */
  public void calculateStatistics() {
    this.numTrials = results.size();
    this.overallData = BenchmarkingUtility.calculateSum(this.results) / 1E6;
    this.meanData = BenchmarkingUtility.calculateMean(this.results) / 1E6;
    double[] ci =
      BenchmarkingUtility.calculateConfidenceInterval(this.results, 0.95);
    this.confidenceInterval = new double[]{
      ci[0] / 1E6,
      ci[1] / 1E6
    };
    this.percentile25Data =
      BenchmarkingUtility.calculatePercentile(this.results, 0.25) / 1E6;
    this.medianData = BenchmarkingUtility.calculateMedian(this.results) / 1E6;
    this.percentile75Data =
      BenchmarkingUtility.calculatePercentile(this.results, 0.75) / 1E6;
    this.rangeData =
      (BenchmarkingUtility.getMax(this.results) - BenchmarkingUtility.getMin(this.results))
        / 1E6;
    this.stdDeviationData =
      BenchmarkingUtility.calculateStandardDeviation(this.results) / 1E6;
    this.varianceData =
      BenchmarkingUtility.calculateVariance(this.results) / (1E6 * 1E6);
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
   * @return An array containing the lower and upper bounds of the confidence
   * interval.
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

  /**
   * Exports statistical data to a CSV file.
   *
   * @param fileName The name of the file to which the statistics are to be
   *                 exported.
   * @throws IOException If there is an issue in file writing.
   */
  public void exportStatisticsToCSV(String fileName) throws IOException {
    File statsFile = FileHandle.createUniqueFile(fileName.replace("/", "-"));

    try (BufferedWriter statsWriter =
           new BufferedWriter(new FileWriter(statsFile))) {
      // Writing the headers
      statsWriter.write("Statistic,Value\n");

      // Writing each statistic
      writeStatisticLine(statsWriter, "Number of Trials",
        String.valueOf(numTrials));
      writeStatisticLine(statsWriter, "Overall Time", String.format("%.5f ms"
        , overallData));
      writeStatisticLine(statsWriter, "Mean", String.format("%.5f ms",
        meanData));
      writeStatisticLine(statsWriter, "Confidence Interval",
        "95% with bounds " + String.format("%.5f ms - %.5f ms",
          confidenceInterval[0],
          confidenceInterval[1]));
      writeStatisticLine(statsWriter, "25th Percentile",
        String.format("%.5f ms", percentile25Data));
      writeStatisticLine(statsWriter, "Median", String.format("%.5f ms",
        medianData));
      writeStatisticLine(statsWriter, "75th Percentile",
        String.format("%.5f ms", percentile75Data));
      writeStatisticLine(statsWriter, "Range", String.format("%.5f ms",
        rangeData));
      writeStatisticLine(statsWriter, "Standard Deviation",
        String.format("%.5f ms", stdDeviationData));
      writeStatisticLine(statsWriter, "Variance", String.format("%.5f ms",
        varianceData));
      writeStatisticLine(statsWriter, "Minimum Time", String.format("%.5f ms"
        , minTimeData));
      writeStatisticLine(statsWriter, "Maximum Time", String.format("%.5f ms"
        , maxTimeData));
      if (hashFunctionName != null) {
        writeStatisticLine(statsWriter, "Hash Function", hashFunctionName);
      }
    }
  }

  /**
   * Writes a line of statistic and its value to the BufferedWriter.
   *
   * @param writer        The BufferedWriter to write to.
   * @param statisticName The name of the statistic.
   * @param value         The value of the statistic.
   * @throws IOException If there is an issue in writing to the file.
   */
  private void writeStatisticLine(BufferedWriter writer, String statisticName
    , String value)
    throws IOException {
    writer.write(statisticName + "," + value + "\n");
  }

  /**
   * Exports benchmarking results (for all individual trials) to a CSV file.
   *
   * @param fileName The name of the file to which results are to be exported.
   * @throws IOException If an I/O error occurs.
   */
  public void exportResultsToCSV(String fileName) throws IOException {
    File resultsFile = FileHandle.createUniqueFile(fileName);
    try (BufferedWriter writer =
           new BufferedWriter(new FileWriter(resultsFile))) {
      // Write the header lines
      writeStatisticLine(writer, "Number of Trials", String.valueOf(numTrials));
      writeStatisticLine(writer, "Overall Time", String.valueOf(overallData));
      writer.newLine();

      // Write each result
      for (int i = 0; i < results.size(); i++) {
        String line = (i + 1) + "," + results.get(i) / 1E6; // Convert
        // nanoseconds to milliseconds
        writer.write(line);
        writer.newLine();
      }
    }
  }

  /**
   * Sets the name of the hash function used in the benchmarking run. This
   * method updates the model
   * with the specified hash function name, allowing for the identification
   * and categorisation of
   * benchmarking results based on the hash function used.
   *
   * @param hashFunctionName The name of the hash function used in the
   *                         benchmarking process.
   */
  public void setHashFunctionName(String hashFunctionName) {
    this.hashFunctionName = hashFunctionName;
  }

  /**
   * Sets the length of the key used in the benchmarking run. This method
   * updates the model with the
   * specified key length, measured in bits.
   *
   * @param keyLength The length of the key used in the benchmarking process,
   *                 in bits.
   */
  public void setKeyLength(int keyLength) {
    this.keyLength = keyLength;
  }

}
