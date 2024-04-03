package uk.msci.project.rsa;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import javafx.concurrent.Task;
import javafx.event.ActionEvent;
import javafx.scene.control.ButtonType;
import javafx.scene.control.Dialog;
import javafx.scene.control.Label;
import javafx.scene.control.ProgressBar;
import javafx.stage.Stage;
import org.apache.commons.math3.distribution.NormalDistribution;
import org.apache.commons.math3.distribution.TDistribution;
import org.apache.commons.math3.exception.NotStrictlyPositiveException;
import org.apache.commons.math3.stat.descriptive.DescriptiveStatistics;


/**
 * This class provides helper methods for facilitating statistical analysis of time measurements and
 * launching/managing benchmarking tasks.
 */
public class BenchmarkingUtility {

  /**
   * The progress bar used to display the progress of a benchmarking task.
   */
  ProgressBar progressBar;

  /**
   * The label used to display the textual representation of the progress of a benchmarking task.
   */
  Label progressLabel;


  /**
   * Starts the benchmarking process by displaying a progress dialog and initiating the provided
   * benchmarking task. Also sets up the task completion behaviour.
   *
   * @param title            The title for the progress dialog.
   * @param benchmarkingTask The task to be executed for benchmarking.
   * @param primaryStage     The primary stage of the application.
   * @param onCompletion     The Runnable to be executed upon successful completion of the task.
   */
  void launchBenchmarkingTask(String title, Task<Void> benchmarkingTask,
      Stage primaryStage, Runnable onCompletion) {
    Dialog<Void> progressDialog = uk.msci.project.rsa.DisplayUtility.showProgressDialog(
        primaryStage, title);
    progressBar = (ProgressBar) progressDialog.getDialogPane()
        .lookup("#progressBar");
    progressLabel = (Label) progressDialog.getDialogPane().lookup("#progressLabel");

    new Thread(benchmarkingTask).start();

    // Set up task completion behavior
    benchmarkingTask.setOnSucceeded(e -> {
      progressDialog.close();
      onCompletion.run();
    });
    benchmarkingTask.setOnFailed(e -> {
      progressDialog.close();
      uk.msci.project.rsa.DisplayUtility.showErrorAlert(
          "Error: Benchmarking failed. Please try again.");
    });

    progressDialog.getDialogPane().lookupButton(ButtonType.CANCEL)
        .addEventFilter(ActionEvent.ACTION, e -> {
          if (benchmarkingTask.isRunning()) {
            benchmarkingTask.cancel();
          }
        });
  }

  /**
   * Begins the benchmarking process using the provided BenchmarkingUtility instance. This method is
   * a static utility to start the benchmarking process with a predefined utility instance.
   *
   * @param benchmarkingUtil The BenchmarkingUtility instance to use for managing the process.
   * @param title            The title for the progress dialog.
   * @param benchmarkingTask The task to be executed for benchmarking.
   * @param onCompletion     The Runnable to be executed upon successful completion of the task.
   * @param primaryStage     The primary stage of the application.
   */
  static void beginBenchmarkWithUtility(BenchmarkingUtility benchmarkingUtil, String title,
      Task<Void> benchmarkingTask, Runnable onCompletion, Stage primaryStage) {
    benchmarkingUtil.launchBenchmarkingTask(title, benchmarkingTask,
        primaryStage, onCompletion);
  }


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
      try {
        TDistribution tDistribution = new TDistribution(n - 1);
        criticalValue = tDistribution.inverseCumulativeProbability(1.0 - (1 - confidenceLevel) / 2);
      } catch (NotStrictlyPositiveException e) {
        return new double[]{0, 0};
      }

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

  /**
   * Updates the progress bar with the given progress value.
   *
   * @param progress The progress value to set on the progress bar, ranging from 0.0 to 1.0.
   */
  public void updateProgress(double progress) {
    this.progressBar.setProgress(progress);
  }

  /**
   * Updates the progress label with the given text.
   *
   * @param text The text to set on the progress label.
   */
  public void updateProgressLabel(String text) {
    this.progressLabel.setText(text);
  }
}
