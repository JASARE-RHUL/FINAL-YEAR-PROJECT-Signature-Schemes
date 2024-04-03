package uk.msci.project.rsa;

import java.util.List;


/**
 * The {@code StatisticData} class represents a single statistic, including its name and value,
 * for display in the results view. This class supports both single-value and multi-value statistics.
 */
public class StatisticData {

  /**
   * The name of the statistic.
   */
  private String statisticName;

  /**
   * The value of the statistic.
   */
  private String statisticValue;

  /**
   * A list of values for the statistic. Used when the statistic has multiple values.
   */
  private List<String> statisticValues;


  /**
   * Constructs a {@code StatisticData} object with a specified name and value.
   *
   * @param statisticName  The name of the statistic.
   * @param statisticValue The value of the statistic.
   */
  public StatisticData(String statisticName, String statisticValue) {
    this.statisticName = statisticName;
    this.statisticValue = statisticValue;
  }

  /**
   * Constructs a {@code StatisticData} object with a specified name and multiple values.
   *
   * @param statisticName   The name of the statistic.
   * @param statisticValues The list of values for the statistic.
   */
  public StatisticData(String statisticName, List<String> statisticValues) {
    this.statisticName = statisticName;
    this.statisticValues = statisticValues;
  }

  /**
   * Returns the name of the statistic.
   *
   * @return The name of the statistic.
   */
  public String getStatisticName() {
    return statisticName;
  }

  /**
   * Sets the name of the statistic.
   *
   * @param statisticName The name to set for the statistic.
   */
  public void setStatisticName(String statisticName) {
    this.statisticName = statisticName;
  }

  /**
   * Returns the value of the statistic.
   *
   * @return The value of the statistic.
   */
  public String getStatisticValue() {
    return statisticValue;
  }

  /**
   * Sets the value of the statistic.
   *
   * @param statisticValue The value to set for the statistic.
   */
  public void setStatisticValue(String statisticValue) {
    this.statisticValue = statisticValue;
  }

  /**
   * Returns the list of values for the statistic.
   *
   * @return The list of values for the statistic, or null if only a single value is set.
   */
  public List<String> getStatisticValues() {
    return statisticValues;
  }

  /**
   * Sets the list of values for the statistic.
   *
   * @param statisticValues The list of values to set for the statistic.
   */
  public void setStatisticValues(List<String> statisticValues) {
    this.statisticValues = statisticValues;
  }
}
