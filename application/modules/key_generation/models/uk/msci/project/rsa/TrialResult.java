package uk.msci.project.rsa;

import java.util.List;

/**
 * This class represents the result of a key generation trial, encapsulating
 * individual key generation times and the total time for the batch.
 */
public class TrialResult {
  /**
   * The list of individual key generation times for this trial.
   */
  private final List<Long> individualKeyTimes;

  /**
   * The total time taken for the batch of key generations in this trial.
   */
  private final long batchTime;

  /**
   * Constructs a new TrialResult with the specified individual key times and batch time.
   *
   * @param individualKeyTimes the individual key generation times
   * @param batchTime the total time for the batch
   */
  public TrialResult(List<Long> individualKeyTimes, long batchTime) {
    this.individualKeyTimes = individualKeyTimes;
    this.batchTime = batchTime;
  }

  /**
   * Gets the individual key generation times.
   *
   * @return a list of individual key generation times
   */
  public List<Long> getIndividualKeyTimes() {
    return individualKeyTimes;
  }

  /**
   * Gets the total batch time.
   *
   * @return the total time for the batch
   */
  public long getBatchTime() {
    return batchTime;
  }
}
