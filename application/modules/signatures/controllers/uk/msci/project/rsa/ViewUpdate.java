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
   * @param visible {@code true} to make the cancel import key button visible, {@code false} otherwise.
   */
  void setCancelImportKeyButtonVisibility(boolean visible);

  /**
   * Sets the visibility of the button to import a batch of keys.
   *
   * @param visible {@code true} to make the import key batch button visible, {@code false} otherwise.
   */
  void setImportKeyBatchButtonVisibility(boolean visible);

  /**
   * Sets a fixed name for the key display area in the user interface.
   */
  void setFixedKeyName();

  /**
   * Sets the visibility of the button to import a batch of text messages.
   *
   * @param visible {@code true} to make the import text batch button visible, {@code false} otherwise.
   */
  void setImportTextBatchBtnVisibility(boolean visible);

  /**
   * Sets the visibility of the button to cancel the import of a text message batch.
   *
   * @param visible {@code true} to make the cancel import text button visible, {@code false} otherwise.
   */
  void setCancelImportTextButtonVisibility(boolean visible);
}
