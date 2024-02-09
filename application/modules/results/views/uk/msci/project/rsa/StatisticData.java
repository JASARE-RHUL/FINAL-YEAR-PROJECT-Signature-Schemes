package uk.msci.project.rsa;
/**
 * The {@code StatisticData} class represents a single statistic, including its name and value,
 * for display in the results view.
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
}
