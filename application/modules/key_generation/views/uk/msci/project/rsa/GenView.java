package uk.msci.project.rsa;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;
import javafx.application.Platform;
import javafx.beans.value.ChangeListener;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.scene.Node;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonBar.ButtonData;
import javafx.scene.control.ButtonType;
import javafx.scene.control.CheckBox;
import javafx.scene.control.Dialog;
import javafx.scene.control.DialogPane;
import javafx.scene.control.Label;
import javafx.scene.control.ProgressBar;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.ScrollPane.ScrollBarPolicy;
import javafx.scene.control.TextField;
import javafx.scene.effect.GaussianBlur;
import javafx.scene.image.ImageView;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.Modality;
import javafx.stage.Stage;
import javafx.util.Pair;
import org.controlsfx.control.ToggleSwitch;


/**
 * The domain object corresponding to GenView FXML file that will serve as a controllers interface
 * into observing and manipulating the graphical layout of the view.
 */
public class GenView {

  /**
   * ImageView that possibly contains a logo or relevant image for the application.
   */
  @FXML
  private ImageView logoImageView;

  /**
   * TextField for the user to enter the desired key sizes, separated by commas.
   */
  @FXML
  private TextField keySizeTextField;

  /**
   * Button that triggers the generation of keys when clicked.
   */
  @FXML
  private Button generateButton;

  /**
   * TextField for the user to enter the desired number of keys.
   */
  @FXML
  private TextField numKeysTextField;

  /**
   * Button that triggers the dynamic generation of corresponding text fields for user to input
   * multiple keys
   */
  @FXML
  private Button numKeysButton;

  /**
   * VBox that contains elements to be shown when key generation is successful.
   */
  @FXML
  private VBox successPopup;

  /**
   * VBox that contains elements to be displayed when key generation fails.
   */
  @FXML
  private VBox failurePopup;

  /**
   * Label to display failure messages.
   */
  @FXML
  private Label failureLabel;

  /**
   * Button to export the generated private key.
   */
  @FXML
  private Button exportPrivateKeyButton;

  /**
   * Button to export the generated public key.
   */
  @FXML
  private Button exportPublicKeyButton;

  /**
   * Button to navigate back to the main menu.
   */
  @FXML
  private Button backToMainMenuButton;

  /**
   * Button that provides help information when clicked.
   */
  @FXML
  private Button helpButton;

  /**
   * List of pairs, each holding an array of integers and a boolean.
   * This list stores dynamic key data, where each pair consists of an array representing key sizes
   * and a boolean indicating whether a small exponent 'e' is used.
   */
  private List<Pair<int[], Boolean>> dynamicKeyData = new ArrayList<>();


  /**
   * Integer holding the number of trials for key generation. This is used primarily in benchmarking
   * mode to specify how many times key generation should be performed per key.
   */
  private int numTrials;


  /**
   * Toggle switch for enabling or disabling benchmarking mode.
   */
  @FXML
  private ToggleSwitch benchmarkingModeToggle;

  /**
   * VBox for standard key generation mode. This VBox contains the UI elements relevant to the
   * standard key generation mode, including input fields for key size and the generate keys
   * button.
   */
  @FXML
  private VBox standardModeVBox;

  /**
   * VBox for benchmarking mode. This VBox contains UI elements specific to the benchmarking mode,
   * such as the field for entering the number of keys to be generated.
   */
  @FXML
  private VBox benchmarkingModeVBox;


  /**
   * Gets the ImageView that may contain a logo.
   *
   * @return ImageView the ImageView component.
   */
  public ImageView getLogoImageView() {
    return logoImageView;
  }

  /**
   * Sets the logo image view.
   *
   * @param logoImageView The ImageView to set.
   */
  public void setLogoImageView(ImageView logoImageView) {
    this.logoImageView = logoImageView;
  }

  /**
   * Retrieves the key size specified in the TextField.
   *
   * @return String the key size text.
   */
  public String getKeySize() {
    return keySizeTextField.getText();
  }

  /**
   * Retrieves the number of keys specified in the corresponding TextField.
   *
   * @return String the number of keys represented as text.
   */
  public String getNumKeys() {
    return numKeysTextField.getText();
  }

  public void setNumKeys(String text) {
    numKeysTextField.setText(text);
  }

  /**
   * Sets the key size in the TextField.
   *
   * @param keySize A string representing the key size.
   */
  public void setKeySize(String keySize) {
    this.keySizeTextField.setText(keySize);
  }

  /**
   * Sets the failure message label text.
   *
   * @param label The failure message to display.
   */
  public void setFailureLabel(String label) {
    this.failureLabel.setText(label);
  }

  /**
   * Gets the VBox that is shown on successful key generation.
   *
   * @return VBox the success popup component.
   */
  public VBox getSuccessPopup() {
    return successPopup;
  }

  /**
   * Sets the visibility of the success popup.
   *
   * @param visible A boolean to set the popup's visibility.
   */
  public void setSuccessPopupVisible(boolean visible) {
    this.successPopup.setVisible(visible);
    this.successPopup.setManaged(visible);
  }

  /**
   * Sets the visibility of the failure popup.
   *
   * @param visible A boolean to set the popup's visibility.
   */
  public void setFailurePopupVisible(boolean visible) {
    this.failurePopup.setVisible(visible);
  }

  /**
   * Registers an observer for the generate button action event.
   *
   * @param observer The event handler to observe the action.
   */
  void addGenerateButtonObserver(EventHandler<ActionEvent> observer) {
    generateButton.setOnAction(observer);
  }

  /**
   * Registers an observer for the export private key button action event.
   *
   * @param observer The event handler to observe the action.
   */
  void addExportPrivateKeyObserver(EventHandler<ActionEvent> observer) {
    exportPrivateKeyButton.setOnAction(observer);
  }

  /**
   * Registers an observer for the export public key button action event.
   *
   * @param observer The event handler to observe the action.
   */
  void addExportPublicKeyObserver(EventHandler<ActionEvent> observer) {
    exportPublicKeyButton.setOnAction(observer);
  }

  /**
   * Registers an observer for the back to main menu button action event.
   *
   * @param observer The event handler to observe the action.
   */
  void addBackToMainMenuObserver(EventHandler<ActionEvent> observer) {
    backToMainMenuButton.setOnAction(observer);
  }

  /**
   * Registers an observer for the help button action event.
   *
   * @param observer The event handler to observe the action.
   */
  void addHelpObserver(EventHandler<ActionEvent> observer) {
    helpButton.setOnAction(observer);
  }

  /**
   * Registers an observer for the number of keys button click event.
   *
   * @param observer The event handler to observe the action.
   */
  void addNumKeysObserver(EventHandler<ActionEvent> observer) {
    numKeysButton.setOnAction(observer);
  }

  /**
   * Displays a dialog for dynamic field generation based on the number of fields specified. This
   * method allows users to enter multiple key sizes and small e selections.
   *
   * @param numberOfFields The number of key fields to be generated in the dialog.
   * @param primaryStage   The primary stage of the application.
   * @return boolean indicating if the dialog submission was completed successfully.
   */
  boolean showDynamicFieldsDialog(int numberOfFields, Stage primaryStage) {
    Dialog<Void> dialog = new Dialog<>();
    dialog.setTitle("Key Size Fields");
    dialog.initModality(Modality.APPLICATION_MODAL);
    dialog.initOwner(primaryStage);

    // Create the VBox to hold fields and checkboxes
    VBox content = new VBox(10);
    //    Label errorLabel = new Label(); // Label to show error messages
    //    errorLabel.setStyle("-fx-text-fill: red;"); // Optional styling for the error label

    // Generate the dynamic fields
    for (int i = 0; i < numberOfFields; i++) {
      TextField textField = new TextField();
      textField.setPromptText("Key " + (i + 1));
      CheckBox checkBox = new CheckBox("Small e?");
      HBox hbox = new HBox(10, textField, checkBox);
      content.getChildren().add(hbox);
    }
    ScrollPane scrollPane = new ScrollPane(content);
    scrollPane.setVbarPolicy(ScrollBarPolicy.AS_NEEDED);
    scrollPane.setHbarPolicy(ScrollBarPolicy.NEVER); // Disable horizontal scrolling
    scrollPane.setFitToWidth(true);

    //    content.getChildren().add(errorLabel); // Add the error label to the content
    ButtonType okButtonType = new ButtonType("Submit", ButtonData.OK_DONE);
    ButtonType cancelButtonType = new ButtonType("Cancel", ButtonData.CANCEL_CLOSE);

    // Set the dialog content and buttons
    DialogPane dialogPane = dialog.getDialogPane();
    dialogPane.setContent(scrollPane);
    dialogPane.getButtonTypes().addAll(okButtonType, cancelButtonType);
    dialogPane.setPrefSize(275, 250);

    final boolean[] isCompleted = {false};

    Button okButton = (Button) dialogPane.lookupButton(okButtonType);
    okButton.addEventFilter(ActionEvent.ACTION, event -> {
      if (isValidInput(content)) {
        isCompleted[0] = true;
        dialog.close();
      } else {
        event.consume(); // Prevent dialog from closing
      }
    });

    primaryStage.getScene().getRoot().setEffect(new GaussianBlur());

    dialog.setOnHidden(e -> primaryStage.getScene().getRoot().setEffect(null));
    dialog.showAndWait();

    return isCompleted[0];
  }

  /**
   * Validates the input provided in the dynamic fields within the given VBox. It checks if the text
   * fields contain valid key size patterns and updates `dynamicKeyData` with the entered key sizes
   * and small e options. If invalid input is detected, the method highlights the respective text
   * field(s) and returns false.
   *
   * @param content The VBox containing dynamically generated text fields and checkboxes.
   * @return boolean indicating whether the input in all text fields is valid.
   */
  private boolean isValidInput(VBox content) {
    dynamicKeyData.clear();
    boolean invalidField = false;
    for (Node node : content.getChildren()) {
      if (node instanceof HBox) {
        HBox hbox = (HBox) node;
        TextField textField = (TextField) hbox.getChildren().get(0);
        CheckBox checkBox = (CheckBox) hbox.getChildren().get(1);

        textField.setStyle("");

        if (!(Pattern.compile("^\\s*\\d+\\s*(,\\s*\\d+\\s*)*$").matcher(textField.getText())
            .matches())) {
          invalidField = true;
          textField.setStyle("-fx-control-inner-background: #FFDDDD;");
        } else {
          String textFieldValue = textField.getText();
          boolean checkBoxValue = checkBox.isSelected();
          dynamicKeyData.add(
              new Pair<>(KeyGenUtil.convertStringToIntArray(textFieldValue), checkBoxValue));

        }

      }
    }
    return !invalidField;
  }


  /**
   * Displays a dialog for entering the number of trials for key generation. This method allows
   * users to input the number of trials for benchmarking.
   *
   * @param primaryStage The primary stage of the application.
   * @return boolean indicating if the dialog submission was completed successfully.
   */
  boolean showTrialsDialog(Stage primaryStage) {
    // Create a new dialog for the number of trials
    Dialog<Integer> trialsDialog = new Dialog<>();
    trialsDialog.setTitle("Number of Trials");
    trialsDialog.initModality(Modality.APPLICATION_MODAL);
    trialsDialog.initOwner(primaryStage);

    // Set up the input field for the number of trials
    TextField trialsField = new TextField();
    trialsField.setPromptText("Enter number of trials");
    final boolean[] isCompleted = {false};
    // Add an event filter to validate input
    trialsDialog.getDialogPane().getButtonTypes().addAll(ButtonType.OK, ButtonType.CANCEL);
    Button okButton = (Button) trialsDialog.getDialogPane().lookupButton(ButtonType.OK);
    okButton.addEventFilter(ActionEvent.ACTION, event -> {
      try {
        numTrials = Integer.parseInt(trialsField.getText());
        isCompleted[0] = true;
      } catch (NumberFormatException e) {
        // Show an error alert if the input is not a valid integer
        uk.msci.project.rsa.DisplayUtility.showErrorAlert(
            "You must provide a valid number of trials. Please try again.");
        event.consume(); // Prevent the dialog from closing
      }
    });

    // Set the content of the dialog
    trialsDialog.getDialogPane().setContent(trialsField);
    trialsDialog.getDialogPane().setPrefSize(300, 150);

    primaryStage.getScene().getRoot().setEffect(new GaussianBlur());

    trialsDialog.setOnHidden(e -> primaryStage.getScene().getRoot().setEffect(null));

    trialsDialog.showAndWait();
    return isCompleted[0];
  }

  /**
   * Retrieves a list of key parameters (sizes and small e options) specified by the user.
   *
   * @return List<Pair < int [ ], Boolean>> containing the key parameters.
   */
  public List<Pair<int[], Boolean>> getDynamicKeyData() {
    return dynamicKeyData;
  }

  /**
   * Retrieves the number of trials specified for key generation.
   *
   * @return int representing the number of trials.
   */
  public int getNumTrials() {
    return numTrials;
  }

  /**
   * Registers an observer for when the benchmarking mode toggle switch value changes.
   *
   * @param observer The change listener to be registered.
   */
  public void addBenchmarkingModeToggleObserver(ChangeListener<Boolean> observer) {
    benchmarkingModeToggle.selectedProperty().addListener(observer);
  }

  /**
   * Sets the visibility of the standardModeVBox.
   * @param visible A boolean indicating whether the standardModeVBox should be visible.
   */
  public void setStandardModeVBoxVisibility(boolean visible) {
    standardModeVBox.setVisible(visible);
    standardModeVBox.setManaged(visible);
  }


  /**
   * Sets the visibility of the benchmarkingModeVBox.
   * @param visible A boolean indicating whether the benchmarkingModeVBox should be visible.
   */
  public void setBenchmarkingModeVBoxVisibility(boolean visible) {
    benchmarkingModeVBox.setVisible(visible);
    benchmarkingModeVBox.setManaged(visible);
  }


  /**
   * Sets the visibility of the numKeysButton.
   * @param visible A boolean indicating whether the numKeysButton should be visible.
   */
  public void setNumKeysButtonVisibility(boolean visible) {
    numKeysButton.setVisible(visible);
    numKeysButton.setManaged(visible);
  }


  /**
   * Sets the visibility of the generateButton.
   * @param visible A boolean indicating whether the generateButton should be visible.
   */
  public void setGenerateButtonVisibility(boolean visible) {
    generateButton.setVisible(visible);
    generateButton.setManaged(visible);
  }



}
