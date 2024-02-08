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
}
