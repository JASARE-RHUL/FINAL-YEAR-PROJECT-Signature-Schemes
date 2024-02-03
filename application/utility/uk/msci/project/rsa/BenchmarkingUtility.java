package uk.msci.project.rsa;

import java.util.ArrayList;

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


}
