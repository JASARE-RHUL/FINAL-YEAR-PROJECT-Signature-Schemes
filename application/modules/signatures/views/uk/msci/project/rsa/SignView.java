package uk.msci.project.rsa;


import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.layout.HBox;

/**
 * The {@code SignView} class is responsible for managing the user interface related to the signing
 * process in the Signature Scheme application.
 */
public class SignView extends SignatureBaseView {

  /**
   * Button to trigger the creation of a digital signature based on the provided text and selected
   * key.
   */
  @FXML
  private Button createSignatureButton;

  /**
   * Button to trigger the export of the generated signature to a file.
   */
  @FXML
  private Button exportSignatureButton;

  /**
   * Button to trigger copying the generated signature to the clipboard.
   */
  @FXML
  private Button copySignatureButton;

  /**
   * Button to trigger the export of the non-recoverable message to a file.
   */
  @FXML
  private Button exportNonRecoverableMessageButton;

  /**
   * Button to trigger copying the non-recoverable message to the clipboard.
   */
  @FXML
  private Button copyNonRecoverableMessageButton;

  /**
   * Button to close the notification pane.
   */
  @FXML
  private Button closeNotificationButton;


  /**
   * Button for starting signature benchmarking.
   */
  @FXML
  private Button SigBenchmarkButton;

  /**
   * Horizontal Box containing options for recovery actions.
   */
  @FXML
  private HBox recoveryOptions;


  /**
   * HBox for inputting the number of messages in benchmarking mode. Contains elements to specify
   * the number of trials or messages to be used in benchmarking.
   */
  @FXML
  private HBox benchmarkingModeNumMessageHBox;


  /**
   * Sets the visibility of the SigBenchmarkButton and manages its properties.
   *
   * @param visible true to make the SigBenchmarkButton visible, false to hide it.
   */
  public void setSigBenchmarkButtonVisibility(boolean visible) {
    SigBenchmarkButton.setVisible(visible);
    SigBenchmarkButton.setManaged(visible);
  }


  /**
   * Registers an observer for the create signature button click action.
   *
   * @param observer The event handler to register.
   */
  void addCreateSignatureObserver(EventHandler<ActionEvent> observer) {
    createSignatureButton.setOnAction(observer);
  }


  /**
   * Registers an observer for the SigBenchmarkButton Button's action event.
   *
   * @param observer The event handler to be registered.
   */
  public void addSigBenchmarkButtonObserver(EventHandler<ActionEvent> observer) {
    SigBenchmarkButton.setOnAction(observer);
  }


  /**
   * Registers an observer for the exportSignatureButton Button's action event.
   *
   * @param observer The event handler to be registered.
   */
  void addExportSignatureObserver(EventHandler<ActionEvent> observer) {
    exportSignatureButton.setOnAction(observer);
  }

  /**
   * Registers an observer for the copySignatureButton Button's action event.
   *
   * @param observer The event handler to be registered.
   */
  void addCopySignatureObserver(EventHandler<ActionEvent> observer) {
    copySignatureButton.setOnAction(observer);
  }

  /**
   * Registers an observer for the exportNonRecoverableMessageButton Button's action event.
   *
   * @param observer The event handler to be registered.
   */
  void addExportNonRecoverableMessageObserver(EventHandler<ActionEvent> observer) {
    exportNonRecoverableMessageButton.setOnAction(observer);
  }

  /**
   * Registers observer for the copyNonRecoverableMessageButton Button's action event.
   *
   * @param observer The event handler to be registered.
   */
  void addCopyNonRecoverableMessageObserver(EventHandler<ActionEvent> observer) {
    copyNonRecoverableMessageButton.setOnAction(observer);
  }

  /**
   * Registers an observer for the closeNotificationButton Button's action event.
   *
   * @param observer The event handler to be registered.
   */
  public void addCloseNotificationObserver(EventHandler<ActionEvent> observer) {
    closeNotificationButton.setOnAction(observer);
  }


  /**
   * Sets the visibility of the benchmarkingModeNumMessageHBox.
   *
   * @param visible true to make the HBox visible, false to hide it.
   */
  public void setBenchmarkingModeNumMessageVBoxVisibility(boolean visible) {
    benchmarkingModeNumMessageHBox.setVisible(visible);
    benchmarkingModeNumMessageHBox.setManaged(visible);
  }


  /**
   * Sets the visibility of the createSignatureButton.
   *
   * @param visible true to make the button visible, false to hide it.
   */
  public void setCreateSignatureButtonVisibility(boolean visible) {
    createSignatureButton.setManaged(visible);
    createSignatureButton.setVisible(visible);
  }

  /**
   * Sets the visibility of the recoveryOptions hBox which contains recovery action options.
   *
   * @param visible true if the recovery options should be visible, false otherwise.
   */
  public void setRecoveryOptionsVisibility(boolean visible) {
    this.recoveryOptions.setVisible(visible);
  }


}
