package uk.msci.project.rsa;

/**
 * Provides implementation of the {@code ViewUpdate} interface specific to the {@code VerifyView}
 * class. This class encapsulates the logic required to update the visual components of the verification
 * view according to the actions defined in the {@code ViewUpdate} interface.
 */
public class VerifyViewUpdateOperations implements ViewUpdate {

  private VerifyView verifyView;

  /**
   * Constructs an update operations object for the verification view.
   *
   * @param verifyView The {@code VerifyView} instance on which operations will be performed.
   */
  public VerifyViewUpdateOperations(VerifyView verifyView) {
    this.verifyView = verifyView;
  }

  /**
   * Sets the name of the key in the verification view.
   *
   * @param keyName The name of the key to be displayed.
   */
  @Override
  public void setKeyName(String keyName) {
    verifyView.setKey(keyName);
  }

  /**
   * Sets the name of the message batch in the verification view.
   *
   * @param name The name of the message batch to be displayed.
   */
  @Override
  public void setMessageBatchName(String name) {
    verifyView.setMessageBatch(name);

  }

  /**
   * Updates the checkmark image in the verification view, typically to indicate a successful operation.
   */
  @Override
  public void updateCheckmarkImage() {
    verifyView.setCheckmarkImage();
  }

  /**
   * Sets the visibility of the checkmark in the verification view.
   *
   * @param visible {@code true} to make the checkmark visible, {@code false} to hide it.
   */
  @Override
  public void setCheckmarkVisibility(boolean visible) {
    verifyView.setCheckmarkImageVisibility(visible);
  }

  /**
   * Sets the visibility of the text file checkmark in the verification view.
   *
   * @param visible {@code true} to make the text file checkmark visible, {@code false} otherwise.
   */
  @Override
  public void setTextFileCheckmarkVisibility(boolean visible) {
    verifyView.setTextFieldCheckmarkImageVisibility(visible);
  }

  /**
   * Sets the visibility of the key display area in the verification view.
   *
   * @param visible {@code true} if the key display should be visible, {@code false} if it should be
   *                hidden.
   */
  @Override
  public void setKeyVisibility(boolean visible) {
    verifyView.setKeyVisibility(visible);
  }

  /**
   * Sets the visibility of the message batch field in the verification view.
   *
   * @param visible {@code true} to make the message batch field visible, {@code false} to hide it.
   */
  @Override
  public void setBatchMessageVisibility(boolean visible) {

  }

  /**
   * Sets the text in the input field within the verification view.
   *
   * @param text The text to be set in the input field.
   */
  @Override
  public void setTextInput(String text) {
    verifyView.setTextInput(text);
  }

  /**
   * Sets the file name label within the verification view to display the name of the loaded file.
   *
   * @param fileName The name of the file to be displayed.
   */
  @Override
  public void setTextFileNameLabel(String fileName) {
    verifyView.setTextFileNameLabel(fileName);
  }

  /**
   * Controls the visibility of the text input field within the verification view.
   *
   * @param visible {@code true} to show the text input field, {@code false} to hide it.
   */
  @Override
  public void setTextInputVisibility(boolean visible) {
    verifyView.setTextInputVisibility(visible);
  }

  /**
   * Updates the image next to the text file input within the verification view, typically with a
   * checkmark to indicate that the text file has been successfully loaded.
   */
  @Override
  public void setTextFileCheckmarkImage() {
    verifyView.setTextFileCheckmarkImage();
  }

  /**
   * Sets the visibility of the container holding the text input elements within the verification view.
   *
   * @param visible {@code true} to make the container visible, {@code false} to hide it.
   */
  @Override
  public void setTextInputHBoxVisibility(boolean visible) {
    verifyView.setTextInputHBoxVisibility(visible);
  }

  /**
   * Retrieves the sign view associated with these operations.
   *
   * @return The associated {@code VerifyView}.
   */
  @Override
  public VerifyView getView() {
    return verifyView;
  }

  /**
   * Controls the visibility of the button used to cancel the import of a key batch in the verification view.
   *
   * @param visible {@code true} to show the cancel import key button, {@code false} to hide it.
   */
  @Override
  public void setCancelImportKeyButtonVisibility(boolean visible) {
    verifyView.setCancelImportKeyButtonVisibility(visible);
  }

  /**
   * Controls the visibility of the button used to import a batch of keys in the verification view.
   *
   * @param visible {@code true} to show the import key batch button, {@code false} to hide it.
   */
  @Override
  public void setImportKeyBatchButtonVisibility(boolean visible) {
    verifyView.setImportKeyBatchButtonVisibility(visible);
  }

  /**
   * Sets a fixed, default text for the key area in the verification view, usually used to prompt the user.
   */
  @Override
  public void setFixedKeyName() {
    verifyView.setKey("Please Import a public key batch");
  }

  /**
   * Controls the visibility of the button used to import a batch of text messages in the verification view.
   *
   * @param visible {@code true} to show the import text batch button, {@code false} to hide it.
   */
  @Override
  public void setImportTextBatchBtnVisibility(boolean visible) {
    verifyView.setImportTextBatchBtnVisibility(visible);
  }

  /**
   * Controls the visibility of the button used to cancel the import of a text message batch in the verification view.
   *
   * @param visible {@code true} to show the cancel import text button, {@code false} to hide it.
   */
  @Override
  public void setCancelImportTextButtonVisibility(boolean visible) {
    verifyView.setCancelImportTextButtonVisibility(visible);
  }

  /**
   * Retrieves the currently selected hash function in the verification view.
   *
   * @return The name of the selected hash function.
   */
  @Override
  public String getSelectedHashFunction() {
    return verifyView.getSelectedHashFunction();
  }

  /**
   * Sets the selected hash function in the verification view.
   *
   * @param scheme The hash function to be selected.
   */
  @Override
  public void setSelectedHashFunction(String scheme) {
    verifyView.setSelectedHashFunction(scheme);
  }

  /**
   * Updates the hash function dropdown for custom or provably secure parameter selections in the
   * verification view.
   */
  @Override
  public void updateHashFunctionDropdownForCustomOrProvablySecure() {
    verifyView.updateHashFunctionDropdownForCustomOrProvablySecure();
  }

  /**
   * Updates the hash function dropdown for standard parameter selections in the verification view.
   */
  @Override
  public void updateHashFunctionDropdownForStandard() {
    verifyView.updateHashFunctionDropdownForStandard();

  }

  /**
   * Retrieves the parameter choice (e.g., 'Standard', 'Provably Secure', 'Custom') selected in the
   * verification view.
   *
   * @return The selected parameter choice.
   */
  @Override
  public String getParameterChoice() {
    return verifyView.getParameterChoice();
  }

  /**
   * Sets the visibility of the hash output size field in the verification view.
   *
   * @param visible {@code true} to make the field visible, {@code false} to hide it.
   */
  @Override
  public void setHashOutputSizeFieldVisibility(boolean visible) {
    verifyView.setHashOutputSizeFieldVisibility(visible);
  }

  /**
   * Retrieves the hash output size entered into the verification view.
   *
   * @return The hash output size as a string.
   */
  @Override
  public String getHashOutputSize() {
    return verifyView.getHashOutputSize();
  }

  /**
   * Resets the hash output size field to its default state in the verification view.
   */
  @Override
  public void resetHashField() {
    verifyView.resetHashField();
  }

  /**
   * Retrieves the visibility state of the hash output size field in the verification view.
   *
   * @return {@code true} if the field is visible, {@code false} otherwise.
   */
  @Override
  public boolean getHashOutputSizeFieldVisibility() {
    return verifyView.getHashOutputSizeFieldVisibility();
  }


}
