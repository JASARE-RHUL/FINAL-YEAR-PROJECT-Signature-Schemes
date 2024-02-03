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

}
