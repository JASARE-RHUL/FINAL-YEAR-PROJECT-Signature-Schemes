package uk.msci.project.rsa;

/**
 * The {@code ResultsTableColumn} class represents a column in the results table.
 * It encapsulates the name of the column.
 */
public class ResultsTableColumn {

  /**
   * The name of the column.
   */
  private String columnName;

  /**
   * Constructs a new ResultsTableColumn with the given column name.
   *
   * @param columnName The name of the column.
   */
  public ResultsTableColumn(String columnName) {
    this.columnName = columnName;
  }

  /**
   * Retrieves the name of the column.
   *
   * @return The name of the column.
   */
  public String getColumnName() {
    return columnName;
  }

}
