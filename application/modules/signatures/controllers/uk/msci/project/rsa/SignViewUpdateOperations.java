package uk.msci.project.rsa;

/**
 * Provides implementation of the {@code ViewUpdate} interface specific to the {@code SignView} class.
 * This class encapsulates the logic required to update the visual components of the sign view
 * as per the actions defined in the {@code ViewUpdate} interface.
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
   * Sets the visibility of the key display area in the sign view.
   *
   * @param visible {@code true} if the key display should be visible, {@code false} if it should be hidden.
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
   * Sets the visibility of the container holding the text input elements within the sign view.
   *
   * @param visible {@code true} to make the container visible, {@code false} to hide it.
   */
  @Override
  public void setTextInputHBoxVisibility(boolean visible) {
    signView.setTextInputHBoxVisibility(visible);
  }
}
