package uk.msci.project.rsa;

import javafx.beans.property.BooleanProperty;
import javafx.beans.property.SimpleBooleanProperty;
import javafx.beans.property.SimpleStringProperty;
import javafx.beans.property.StringProperty;

/**
 * Represents an item in the hash function selection list within the RSA key generation view.
 * This class holds the name of the hash function and properties to manage user selection
 * and custom hash size specifications.
 */
public class HashFunctionItem {
  /**
   * The name of the hash function, such as "SHA-256" or "SHA-512".
   */
  private final String name;

  /**
   * Property to track whether this hash function is selected by the user.
   */
  private final BooleanProperty checked;

  /**
   * Property to store the user's selection for the hash function's output mode,
   * such as "Standard", "Provably Secure", or "Custom".
   */
  private final StringProperty comboBoxSelection;

  /**
   * Property to store the custom hash size specified by the user when "Custom" mode is selected.
   */
  private final StringProperty customHashSize;

  /**
   * Constructs a new HashFunctionItem with the specified name and initializes properties.
   *
   * @param name The name of the hash function.
   */
  public HashFunctionItem(String name) {
    this.name = name;
    this.checked = new SimpleBooleanProperty(false);
    this.comboBoxSelection = new SimpleStringProperty("");
    this.customHashSize = new SimpleStringProperty("");
  }

  /**
   * Gets the name of the hash function.
   *
   * @return The name of the hash function.
   */
  public String getName() { return name; }

  /**
   * Checks if this hash function item is selected by the user.
   *
   * @return True if selected, false otherwise.
   */
  public boolean isChecked() { return checked.get(); }

  /**
   * Sets the selection status of this hash function item.
   *
   * @param checked True to select the item, false to deselect.
   */
  public void setChecked(boolean checked) { this.checked.set(checked); }

  /**
   * Gets the BooleanProperty representing the selection status.
   *
   * @return The BooleanProperty for checked status.
   */
  public BooleanProperty checkedProperty() { return checked; }

  /**
   * Gets the current selection mode for hash function output (e.g., "Standard", "Provably Secure").
   *
   * @return The selected hash function output mode.
   */
  public String getComboBoxSelection() { return comboBoxSelection.get(); }

  /**
   * Sets the selection mode for hash function output.
   *
   * @param selection The hash function output mode to set.
   */
  public void setComboBoxSelection(String selection) { this.comboBoxSelection.set(selection); }

  /**
   * Gets the StringProperty for hash function output mode selection.
   *
   * @return The StringProperty for comboBoxSelection.
   */
  public StringProperty comboBoxSelectionProperty() { return comboBoxSelection; }

  /**
   * Gets the custom hash size specified by the user.
   *
   * @return The custom hash size.
   */
  public String getCustomHashSize() { return customHashSize.get(); }

  /**
   * Sets the custom hash size as specified by the user.
   *
   * @param size The custom hash size to set.
   */
  public void setCustomHashSize(String size) { this.customHashSize.set(size); }

  /**
   * Gets the StringProperty for custom hash size.
   *
   * @return The StringProperty for customHashSize.
   */
  public StringProperty customHashSizeProperty() { return customHashSize; }
}
