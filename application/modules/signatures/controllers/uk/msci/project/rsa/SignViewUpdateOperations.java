package uk.msci.project.rsa;

/**
 * Provides implementation of the {@code ViewUpdate} interface specific to the {@code SignView}
 * class. This class encapsulates the logic required to update the visual components of the sign
 * view as per the actions defined in the {@code ViewUpdate} interface.
 */
public class SignViewUpdateOperations implements ViewUpdate {

  private SignView signView;

  /**
   * Constructs an update operations object for the sign view.
   *
   * @param signView The {@code SignView} instance on which operations will be performed.
   */
  public SignViewUpdateOperations(SignView signView) {
    this.signView = signView;
  }

  /**
   * Sets the name of the key in the sign view.
   *
   * @param keyName The name of the key to be displayed.
   */
  @Override
  public void setKeyName(String keyName) {
    signView.setKey(keyName);
  }

  /**
   * Sets the name of the message batch in the sign view.
   *
   * @param name The name of the message batch to be displayed.
   */
  @Override
  public void setMessageBatchName(String name) {
    signView.setMessageBatch(name);
  }

  /**
   * Updates the checkmark image in the sign view, typically to indicate a successful operation.
   */
  @Override
  public void updateCheckmarkImage() {
    signView.setCheckmarkImage();
  }

  /**
   * Sets the visibility of the checkmark in the sign view.
   *
   * @param visible {@code true} to make the checkmark visible, {@code false} to hide it.
   */
  @Override
  public void setCheckmarkVisibility(boolean visible) {
    signView.setCheckmarkImageVisibility(visible);
  }


  /**
   * Sets the visibility of the message batch field in the sign view.
   *
   * @param visible {@code true} to make the message batch field visible, {@code false} to hide it.
   */
  @Override
  public void setBatchMessageVisibility(boolean visible) {
    signView.setMessageBatchFieldVisibility(visible);
  }

  /**
   * Sets the visibility of the key display area in the sign view.
   *
   * @param visible {@code true} if the key display should be visible, {@code false} if it should be
   *                hidden.
   */
  @Override
  public void setKeyVisibility(boolean visible) {
    signView.setKeyVisibility(visible);
  }

  /**
   * Sets the text in the input field within the sign view.
   *
   * @param text The text to be set in the input field.
   */
  @Override
  public void setTextInput(String text) {
    signView.setTextInput(text);
  }

  /**
   * Sets the file name label within the sign view to display the name of the loaded file.
   *
   * @param fileName The name of the file to be displayed.
   */
  @Override
  public void setTextFileNameLabel(String fileName) {
    signView.setTextFileNameLabel(fileName);
  }

  /**
   * Controls the visibility of the text input field within the sign view.
   *
   * @param visible {@code true} to show the text input field, {@code false} to hide it.
   */
  @Override
  public void setTextInputVisibility(boolean visible) {
    signView.setTextInputVisibility(visible);
  }

  /**
   * Updates the image next to the text file input within the sign view, typically with a checkmark
   * to indicate that the text file has been successfully loaded.
   */
  @Override
  public void setTextFileCheckmarkImage() {
    signView.setTextFileCheckmarkImage();
  }

  /**
   * Updates the image next to the message batch file input within the sign view, typically with a
   * checkmark to indicate that the text file has been successfully loaded.
   */
  public void setCheckmarkImageMessageBatch() {
    signView.setCheckmarkImageMessageBatch();
  }

  /**
   * Sets the visibility of the text file checkmark in the sign view.
   *
   * @param visible {@code true} to make the text file checkmark visible, {@code false} otherwise.
   */
  public void setTextFileCheckmarkVisibility(boolean visible) {
    signView.setTextFieldCheckmarkImageVisibility(visible);
  }

  /**
   * Sets the visibility of the container holding the text input elements within the sign view.
   *
   * @param visible {@code true} to make the container visible, {@code false} to hide it.
   */
  @Override
  public void setTextInputHBoxVisibility(boolean visible) {
    signView.setTextInputHBoxVisibility(visible);
  }

  /**
   * Retrieves the sign view associated with these operations.
   *
   * @return The associated {@code SignView}.
   */
  @Override
  public SignView getView() {
    return signView;
  }

  /**
   * Controls the visibility of the button used to cancel the import of a key batch in the sign
   * view.
   *
   * @param visible {@code true} to show the cancel import key button, {@code false} to hide it.
   */
  @Override
  public void setCancelImportKeyBatchButtonVisibility(boolean visible) {
    signView.setCancelImportKeyButtonVisibility(visible);
  }


  /**
   * Sets the visibility of the button used to cancel the import of a single key.
   *
   * @param visible true to make the cancel import single key button visible, false to hide it.
   */
  @Override
  public void setCancelImportSingleKeyButtonVisibility(boolean visible) {
    signView.setCancelImportSingleKeyButtonVisibility(visible);
  }


  /**
   * Controls the visibility of the button used to import a batch of keys in the sign view.
   *
   * @param visible {@code true} to show the import key batch button, {@code false} to hide it.
   */
  @Override
  public void setImportKeyBatchButtonVisibility(boolean visible) {
    signView.setImportKeyBatchButtonVisibility(visible);

  }

  /**
   * Sets the visibility of the button used to import a key.
   *
   * @param visible true to make the import key button visible, false to hide it.
   */
  public void setImportKeyButtonVisibility(boolean visible) {
    signView.setImportKeyButtonVisibility(visible);
  }

  /**
   * Sets a fixed, default text for the key area in the verification view, usually used to prompt
   * the user.
   */
  @Override
  public void setFixedKeyName() {
    signView.setKey("Please Import a private key batch");
  }

  /**
   * Controls the visibility of the button used to import a batch of text messages in the sign
   * view.
   *
   * @param visible {@code true} to show the import text batch button, {@code false} to hide it.
   */
  @Override
  public void setImportTextBatchBtnVisibility(boolean visible) {
    signView.setImportTextBatchBtnVisibility(visible);
  }

  /**
   * Sets the visibility of the button used to import text.
   *
   * @param visible true to make the import text button visible, false to hide it.
   */
  public void setImportTextButtonVisibility(boolean visible) {
    signView.setImportTextButtonVisibility(visible);
  }

  /**
   * Controls the visibility of the button used to cancel the import of a text message batch in the
   * sign view.
   *
   * @param visible {@code true} to show the cancel import text button, {@code false} to hide it.
   */
  @Override
  public void setCancelImportTextBatchButtonVisibility(boolean visible) {
    signView.setCancelImportTextBatchButtonVisibility(visible);
  }

  /**
   * Sets the visibility of the button used to cancel the import of text.
   *
   * @param visible true to make the cancel import text button visible, false to hide it.
   */
  public void setCancelImportTextButtonVisibility(boolean visible) {
    signView.setCancelImportTextButtonVisibility(visible);
  }

  /**
   * Retrieves the currently selected hash function in the sign view.
   *
   * @return The name of the selected hash function.
   */
  @Override
  public String getSelectedHashFunction() {
    return signView.getSelectedHashFunction();
  }

  /**
   * Sets the selected hash function in the sign view.
   *
   * @param scheme The hash function to be selected.
   */
  @Override
  public void setSelectedHashFunction(String scheme) {
    signView.setSelectedHashFunction(scheme);
  }

  /**
   * Updates the hash function dropdown for custom or provably secure parameter selections in the
   * sign view.
   */
  @Override
  public void updateHashFunctionDropdownForCustomOrProvablySecure() {
    signView.updateHashFunctionDropdownForCustomOrProvablySecure();
  }

  /**
   * Updates the hash function dropdown for standard parameter selections in the sign view.
   */
  @Override
  public void updateHashFunctionDropdownForStandard() {
    signView.updateHashFunctionDropdownForStandard();

  }

  /**
   * Retrieves the parameter choice (e.g., 'Standard', 'Provably Secure', 'Custom') selected in the
   * sign view.
   *
   * @return The selected parameter choice.
   */
  @Override
  public String getParameterChoice() {
    return signView.getParameterChoice();
  }

  /**
   * Sets the visibility of the hash output size field in the sign view.
   *
   * @param visible {@code true} to make the field visible, {@code false} to hide it.
   */
  @Override
  public void setHashOutputSizeFieldVisibility(boolean visible) {
    signView.setHashOutputSizeFieldVisibility(visible);
  }

  /**
   * Retrieves the hash output size entered into the sign view.
   *
   * @return The hash output size as a string.
   */
  @Override
  public String getHashOutputSize() {
    return signView.getHashOutputSize();
  }

  /**
   * Resets the hash output size field to its default state in the sign view.
   */
  @Override
  public void resetHashField() {
    signView.resetHashField();
  }

  /**
   * Retrieves the visibility state of the hash output size field in the sign view.
   *
   * @return {@code true} if the field is visible, {@code false} otherwise.
   */
  @Override
  public boolean getHashOutputSizeFieldVisibility() {
    return signView.getHashOutputSizeFieldVisibility();
  }
}
