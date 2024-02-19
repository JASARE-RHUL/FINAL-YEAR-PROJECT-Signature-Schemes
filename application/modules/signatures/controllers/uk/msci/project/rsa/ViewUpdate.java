package uk.msci.project.rsa;

/**
 * This interface defines operations for updating independent components from the sign/verify views
 * that behave identically. Implementing classes are expected to provide concrete behavior for these
 * operations, allowing for uniform manipulation of view components across different types of views
 * that share the same update logic.
 */
public interface ViewUpdate {

  /**
   * Sets the name of the key.
   *
   * @param keyName The name of the key to set.
   */
  void setKeyName(String keyName);


  /**
   * Sets the name of the message batch in the view.
   *
   * @param keyName The name of the message batch to be displayed.
   */
  void setMessageBatchName(String keyName);

  /**
   * Updates the checkmark image, typically to indicate a successful operation.
   */
  void updateCheckmarkImage();

  /**
   * Sets the visibility of the checkmark.
   *
   * @param visible {@code true} to make the checkmark visible; {@code false} to hide it.
   */
  void setCheckmarkVisibility(boolean visible);

  /**
   * Sets the visibility of the text file checkmark in the view.
   *
   * @param visible {@code true} to make the text file checkmark visible, {@code false} otherwise.
   */
  void setTextFileCheckmarkVisibility(boolean visible);

  /**
   * Sets the visibility of the key in the user interface.
   *
   * @param visible {@code true} if the key should be visible; {@code false} if it should be
   *                hidden.
   */
  void setKeyVisibility(boolean visible);

  /**
   * Sets the visibility of the message batch section in the view.
   *
   * @param visible {@code true} if the message batch should be visible, {@code false} otherwise.
   */
  void setBatchMessageVisibility(boolean visible);

  /**
   * Sets the text in a text input field.
   *
   * @param text The text to set in the input field.
   */
  void setTextInput(String text);

  /**
   * Sets the label that displays the name of the file.
   *
   * @param fileName The name of the file to display.
   */
  void setTextFileNameLabel(String fileName);

  /**
   * Sets the visibility of a text input field.
   *
   * @param visible {@code true} if the text input should be visible; {@code false} if it should be
   *                hidden.
   */
  void setTextInputVisibility(boolean visible);

  /**
   * Updates the image next to the text file input to indicate a status, typically a checkmark to
   * indicate success.
   */
  void setTextFileCheckmarkImage();

  /**
   * Sets the visibility of the horizontal box (HBox) that contains the text input elements.
   *
   * @param visible {@code true} to make the HBox visible; {@code false} to hide it.
   */
  void setTextInputHBoxVisibility(boolean visible);

  /**
   * Retrieves the view interface associated with this update.
   *
   * @return The associated view interface.
   */
  SignatureViewInterface getView();


  /**
   * Sets the visibility of the button to cancel the import of a key.
   *
   * @param visible {@code true} to make the cancel import key button visible, {@code false}
   *                otherwise.
   */
  void setCancelImportKeyBatchButtonVisibility(boolean visible);


  /**
   * Updates the checkmark image next to the message batch in the view, typically to indicate a
   * successful operation such as the successful import of a message batch.
   */
  void setCheckmarkImageMessageBatch();

  /**
   * Sets the visibility of the button used to cancel the import of a single key in the view.
   *
   * @param visible true to make the cancel import single key button visible, false to hide it.
   */
  void setCancelImportSingleKeyButtonVisibility(boolean visible);

  /**
   * Sets the visibility of the button to import a batch of keys.
   *
   * @param visible {@code true} to make the import key batch button visible, {@code false}
   *                otherwise.
   */
  void setImportKeyBatchButtonVisibility(boolean visible);

  /**
   * Sets the visibility of the button used to import a single key in the view.
   *
   * @param visible true to make the import key button visible, false to hide it.
   */
  void setImportKeyButtonVisibility(boolean visible);

  /**
   * Sets a fixed name for the key display area in the user interface.
   */
  void setFixedKeyName();

  /**
   * Sets the visibility of the button to import a batch of text messages.
   *
   * @param visible {@code true} to make the import text batch button visible, {@code false}
   *                otherwise.
   */
  void setImportTextBatchBtnVisibility(boolean visible);

  /**
   * Sets the visibility of the button used to import text in the view.
   *
   * @param visible true to make the import text button visible, false to hide it.
   */
  void setImportTextButtonVisibility(boolean visible);

  /**
   * Sets the visibility of the button to cancel the import of a text message batch.
   *
   * @param visible {@code true} to make the cancel import text button visible, {@code false}
   *                otherwise.
   */
  void setCancelImportTextBatchButtonVisibility(boolean visible);

  /**
   * Sets the visibility of the button used to cancel the import of text in the view.
   *
   * @param visible true to make the cancel import text button visible, false to hide it.
   */
  void setCancelImportTextButtonVisibility(boolean visible);

  /**
   * Retrieves the name of the selected hash function in the view.
   *
   * @return The name of the selected hash function.
   */
  String getSelectedHashFunction();

  /**
   * Sets the selected hash function in the view.
   *
   * @param scheme The hash function to be selected.
   */
  void setSelectedHashFunction(String scheme);

  /**
   * Updates the hash function dropdown for custom or provably secure parameter selections in the
   * view.
   */
  void updateHashFunctionDropdownForCustomOrProvablySecure();

  /**
   * Updates the hash function dropdown for standard parameter selections in the view.
   */
  void updateHashFunctionDropdownForStandard();

  /**
   * Retrieves the parameter choice (e.g., 'Standard', 'Provably Secure', 'Custom') selected in the
   * view.
   *
   * @return The selected parameter choice.
   */
  String getParameterChoice();

  /**
   * Sets the visibility of the hash output size field in the view.
   *
   * @param visible {@code true} to make the field visible, {@code false} to hide it.
   */
  void setHashOutputSizeFieldVisibility(boolean visible);

  /**
   * Retrieves the hash output size entered in the view.
   *
   * @return The hash output size as a string.
   */
  String getHashOutputSize();

  /**
   * Resets the hash output size field to its default state in the view.
   */
  void resetHashField();

  /**
   * Retrieves the visibility state of the hash output size field in the view.
   *
   * @return {@code true} if the field is visible, {@code false} otherwise.
   */
  boolean getHashOutputSizeFieldVisibility();


}
