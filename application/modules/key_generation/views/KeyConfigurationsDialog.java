package uk.msci.project.rsa;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.scene.Node;
import javafx.scene.control.*;
import javafx.scene.control.ButtonBar.ButtonData;
import javafx.scene.control.ScrollPane.ScrollBarPolicy;
import javafx.scene.effect.GaussianBlur;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.Modality;
import javafx.stage.Stage;
import javafx.util.Pair;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import uk.msci.project.rsa.HashFunctionSelection;
import uk.msci.project.rsa.HashFunctionItem;
import uk.msci.project.rsa.DigestType;

import static uk.msci.project.rsa.HashFunctionSelection.validateFraction;

public class KeyConfigurationsDialog {

  /**
   * Primary stage for the dialog window.
   */
  private Stage primaryStage;
  /**
   * Number of keys grouped together for a shared configuration.
   */
  private int keysPerGroup;
  /**
   * A list storing dynamic key configuration data. Each entry in the list is a pair, where the
   * first element is an array of integers representing key configuration parameters and the second
   * element is a boolean indicating the use of a small 'e' value in the key generation.
   */
  private List<Pair<int[], Boolean>> dynamicKeyConfigurationsData;

  /**
   * Maps each key configuration group to a list of hash function selections. Each entry in the map
   * associates a group index with a list of {@link HashFunctionSelection} instances, representing
   * hash function choices and their provable security status.
   */
  private Map<Integer, List<HashFunctionSelection>> keyConfigToHashFunctionsMap = new HashMap<>();

  /**
   * Constructs a new dialog for setting key configurations.
   *
   * @param primaryStage                 The primary stage of the application.
   * @param dynamicKeyConfigurationsData A list of dynamic key configurations data.
   * @param keyConfigToHashFunctionsMap  A map of key configuration groups to their corresponding
   *                                     hash functions.
   * @param keysPerGroup                 The number of keys per configuration group.
   */
  public KeyConfigurationsDialog(Stage primaryStage,
      List<Pair<int[], Boolean>> dynamicKeyConfigurationsData,
      Map<Integer, List<HashFunctionSelection>> keyConfigToHashFunctionsMap, int keysPerGroup) {
    this.primaryStage = primaryStage;
    this.dynamicKeyConfigurationsData = dynamicKeyConfigurationsData;
    this.keyConfigToHashFunctionsMap = keyConfigToHashFunctionsMap;
    this.keysPerGroup = keysPerGroup;
  }

  /**
   * Shows the key configuration dialog.
   *
   * @param numberOfFields The number of fields to be displayed in the dialog.
   * @return True if the dialog completes successfully, false otherwise.
   */
  boolean showKeyConfigurationsDialog(int numberOfFields) {
    Dialog<Void> dialog = createDialog();

    VBox content = new VBox(10); // Main container for all groups
    addDynamicFields(numberOfFields, content);

    ScrollPane scrollPane = createScrollPane(content);
    ButtonType okButtonType = new ButtonType("Submit", ButtonData.OK_DONE);
    ButtonType cancelButtonType = new ButtonType("Cancel", ButtonData.CANCEL_CLOSE);
    setupDialogPane(dialog, scrollPane, okButtonType, cancelButtonType);

    return showDialog(dialog, content, okButtonType);
  }

  /**
   * Creates and configures the dialog for key configurations.
   *
   * @return A configured Dialog instance.
   */
  private Dialog<Void> createDialog() {
    Dialog<Void> dialog = new Dialog<>();
    dialog.setTitle("Key Configurations");
    dialog.initModality(Modality.APPLICATION_MODAL);
    dialog.initOwner(primaryStage);
    return dialog;
  }

  /**
   * Adds dynamically generated input fields for key configurations to the provided VBox container.
   *
   * @param numberOfFields Number of fields to be added.
   * @param content        The VBox container to which the fields are added.
   */
  private void addDynamicFields(int numberOfFields, VBox content) {
    VBox currentGroup = null;

    for (int i = 0; i < numberOfFields; i++) {
      if (i % keysPerGroup == 0 || currentGroup == null) {
        currentGroup = createNewGroup();
        content.getChildren().add(currentGroup);
      }

      HBox hbox = createInputField();
      currentGroup.getChildren().add(hbox);

      if ((i + 1) % keysPerGroup == 0) {
        addHashFunctionSelection(currentGroup);
      }
    }
  }

  /**
   * Creates a new group VBox with predefined styling for grouping related UI elements.
   *
   * @return A new VBox instance representing a group of UI elements.
   */
  private VBox createNewGroup() {
    VBox currentGroup = new VBox(5);
    currentGroup.setStyle("-fx-padding: 10; -fx-border-style: solid inside; " +
        "-fx-border-width: 2; -fx-border-insets: 5; " +
        "-fx-border-radius: 5; -fx-border-color: blue;");
    return currentGroup;
  }

  /**
   * Creates a horizontal box (HBox) containing a text field and a checkbox for inputting key
   * configuration details.
   *
   * @return A HBox with configured components for key size configuration input.
   */
  private HBox createInputField() {
    TextField textField = new TextField();
    textField.setPrefWidth(450);
    textField.setMinWidth(450);
    textField.setPromptText("Enter multiples fractions, separated by commas");

    CheckBox checkBox = new CheckBox("Small e?");
    checkBox.setMinWidth(75);

    return new HBox(8, textField, checkBox);
  }

  /**
   * Adds hash function selection controls to the given group container.
   *
   * @param currentGroup The group container where hash function controls will be added.
   */
  private void addHashFunctionSelection(VBox currentGroup) {
    Label label = new Label("Group Hash Function(s):");
    label.setMinWidth(140);

    ListView<HashFunctionItem> hashFunctionCheckComboBox = createHashFunctionComboBox();
    HBox hashHbox = new HBox(4, label, hashFunctionCheckComboBox);
    currentGroup.getChildren().add(hashHbox);
  }


  /**
   * Creates and configures a ListView for hash function selection. Each list item is represented by
   * a custom view comprising a CheckBox for selection, a Label for displaying hash function output,
   * a ComboBox for selecting hash function type, and an optional TextField for specifying custom
   * hash function sizes. The ListView allows multiple hash functions to be selected, each with
   * their specific configurations.
   *
   * @return A ListView of HashFunctionItem objects, each representing a hash function with
   * configurable settings.
   */
  private ListView<HashFunctionItem> createHashFunctionComboBox() {
    ListView<HashFunctionItem> hashFunctionCheckComboBox = new ListView<>();
    hashFunctionCheckComboBox.setItems(FXCollections.observableArrayList(
        new HashFunctionItem("SHA-256"),
        new HashFunctionItem("SHA-512"), new HashFunctionItem("SHA-256 with MGF1"),
        new HashFunctionItem("SHA-512 with MGF1"),
        new HashFunctionItem("SHAKE-128"), new HashFunctionItem("SHAKE-256")
    ));

    hashFunctionCheckComboBox.setCellFactory(lv -> new ListCell<>() {
      private final CheckBox checkBox = new CheckBox();
      private final Label label = new Label("Hash Function Output");
      private final ComboBox<String> comboBox = createComboBox();
      private final TextField customTextField = createCustomTextField();
      private final HBox content = new HBox(10, checkBox);

      {
        comboBox.valueProperty().addListener((obs, oldVal, newVal) -> {
          HashFunctionItem currentItem = getItem();
          if (currentItem != null) {
            currentItem.setComboBoxSelection(newVal);
          }
        });

        customTextField.textProperty().addListener((obs, oldVal, newVal) -> {
          HashFunctionItem currentItem = getItem();
          if (currentItem != null) {
            currentItem.setCustomHashSize(newVal);
          }
        });
      }

      @Override
      protected void updateItem(HashFunctionItem item, boolean empty) {
        super.updateItem(item, empty);
        customTextField.setPromptText("Enter hash size as a fraction of each key size (e.g., 1/2)");
        customTextField.setMinWidth(260);

        // Resetting the setup for reuse
        checkBox.setOnAction(null);
        content.getChildren().clear();
        setGraphic(null);

        if (empty || item == null) {
          return; // No item to display
        }

        // Updating checkbox state and setting listeners
        checkBox.setSelected(item.isChecked());
        checkBox.setOnAction(event -> item.setChecked(checkBox.isSelected()));
        checkBox.setText(item.getName());
        content.getChildren().add(checkBox);

        // Conditionally add ComboBox if not fixed size hash
        if (!item.getName().equals("SHA-256") && !item.getName().equals("SHA-512")) {
          content.getChildren().addAll(label, comboBox);
          comboBox.valueProperty().addListener((obs, oldVal, newVal) -> {
            if ("Custom".equals(newVal)) {
              if (!content.getChildren().contains(customTextField)) {
                content.getChildren().addAll(customTextField);
              }
            } else {
              content.getChildren().removeAll(customTextField);
            }
          });
        }

        setGraphic(content);
      }
    });

    hashFunctionCheckComboBox.setPrefWidth(470);
    hashFunctionCheckComboBox.setMinWidth(470);
    hashFunctionCheckComboBox.setPrefHeight(210);
    hashFunctionCheckComboBox.setMinHeight(205);

    return hashFunctionCheckComboBox;
  }


  /**
   * Creates and configures a ComboBox for hash function selection.
   *
   * @return A ComboBox with predefined options for hash function selection.
   */
  private ComboBox<String> createComboBox() {
    return new ComboBox<>(FXCollections.observableArrayList("Provably Secure", "Custom"));
  }

  /**
   * Creates a TextField for entering custom hash function sizes.
   *
   * @return A TextField configured for inputting custom hash function sizes.
   */
  private TextField createCustomTextField() {
    TextField customTextField = new TextField();
    customTextField.setPromptText("Enter Fraction of Modulus Length");
    customTextField.setMinWidth(160);
    return customTextField;
  }

  /**
   * Creates a scroll pane with the given content.
   *
   * @param content The content to be placed inside the scroll pane.
   * @return A ScrollPane containing the provided content.
   */
  private ScrollPane createScrollPane(VBox content) {
    ScrollPane scrollPane = new ScrollPane(content);
    scrollPane.setVbarPolicy(ScrollBarPolicy.AS_NEEDED);
    scrollPane.setHbarPolicy(ScrollBarPolicy.AS_NEEDED);
    scrollPane.setFitToWidth(true);
    return scrollPane;
  }

  /**
   * Sets up the dialog pane with necessary components like scroll pane, buttons, etc.
   *
   * @param dialog           The dialog to which the pane is to be added.
   * @param scrollPane       The scroll pane containing dialog content.
   * @param okButtonType     The ButtonType for the OK button.
   * @param cancelButtonType The ButtonType for the Cancel button.
   */
  private void setupDialogPane(Dialog<Void> dialog, ScrollPane scrollPane, ButtonType okButtonType,
      ButtonType cancelButtonType) {
    DialogPane dialogPane = dialog.getDialogPane();
    dialogPane.getButtonTypes().addAll(okButtonType, cancelButtonType);
    dialogPane.setContent(scrollPane);
    dialogPane.setPrefSize(550, 400);
  }

  /**
   * Displays the dialog and processes user input upon submission.
   *
   * @param dialog       The dialog to be displayed.
   * @param content      The container holding user input fields within the dialog.
   * @param okButtonType The ButtonType for the OK button.
   * @return True if the dialog operation is completed successfully.
   */
  private boolean showDialog(Dialog<Void> dialog, VBox content, ButtonType okButtonType) {
    final boolean[] isCompleted = {false};

    Button okButton = (Button) dialog.getDialogPane().lookupButton(okButtonType);
    okButton.addEventFilter(ActionEvent.ACTION, event -> {
      if (isValidInputMultiPrime(content)) {
        isCompleted[0] = true;
      } else {
        event.consume(); // Prevent dialog from closing
        uk.msci.project.rsa.DisplayUtility.showErrorAlert(
            "You must provide valid input for all required fields, please try again.");
      }
    });

    primaryStage.getScene().getRoot().setEffect(new GaussianBlur());
    dialog.setOnHidden(e -> primaryStage.getScene().getRoot().setEffect(null));
    dialog.showAndWait();

    return isCompleted[0];
  }

  /**
   * Validates the user input for multi-prime RSA configurations.
   *
   * @param content The container holding the user input fields.
   * @return True if the input is valid, false otherwise.
   */
  private boolean isValidInputMultiPrime(VBox content) {
    dynamicKeyConfigurationsData.clear();
    keyConfigToHashFunctionsMap.clear();

    boolean invalidField = false;
    int groupIndex = 0;

    for (Node groupNode : content.getChildren()) {
      if (groupNode instanceof VBox) {
        VBox currentGroup = (VBox) groupNode;
        List<HashFunctionSelection> currentGroupHashFunctionSelections = new ArrayList<>();

        invalidField =
            processGroupNodes(currentGroup, currentGroupHashFunctionSelections, groupIndex)
                || invalidField;
        groupIndex++;
      }
    }
    return !invalidField;
  }

  /**
   * Processes user input from each group in the dialog and updates the key configuration data
   * accordingly.
   *
   * @param currentGroup                       The group containing the input fields.
   * @param currentGroupHashFunctionSelections A list to store selected hash functions for the
   *                                           current group.
   * @param groupIndex                         The index of the current group.
   * @return True if an invalid input is found, false otherwise.
   */
  private boolean processGroupNodes(VBox currentGroup,
      List<HashFunctionSelection> currentGroupHashFunctionSelections, int groupIndex) {
    boolean invalidField = false;

    for (int configIndex = 0; configIndex < currentGroup.getChildren().size(); configIndex++) {
      Node configNode = currentGroup.getChildren().get(configIndex);

      if (configNode instanceof HBox) {
        HBox hbox = (HBox) configNode;

        if (isHashFunctionConfiguration(hbox, configIndex, currentGroup.getChildren().size())) {
          invalidField =
              processHashFunctionConfiguration(hbox, currentGroupHashFunctionSelections, groupIndex)
                  || invalidField;
        } else {
          invalidField = processKeySizeConfiguration(hbox) || invalidField;
        }
      }
    }
    return invalidField;
  }

  /**
   * Checks if a given HBox is for hash function configuration based on its position within the
   * group.
   *
   * @param hbox        The HBox to check.
   * @param configIndex The index of the HBox within its parent group.
   * @param groupSize   The total number of nodes in the group.
   * @return True if the HBox is for hash function configuration, false otherwise.
   */
  private boolean isHashFunctionConfiguration(HBox hbox, int configIndex, int groupSize) {
    return configIndex == groupSize - 1;
  }

  /**
   * Processes the hash function configuration input from the given HBox.
   *
   * @param hbox                               The HBox containing hash function configuration
   *                                           controls.
   * @param currentGroupHashFunctionSelections A list to store selected hash functions for the
   *                                           current group.
   * @param groupIndex                         The index of the current group.
   * @return True if an invalid input is found, false otherwise.
   */
  private boolean processHashFunctionConfiguration(HBox hbox,
      List<HashFunctionSelection> currentGroupHashFunctionSelections, int groupIndex) {
    Node hashFunctionNode = hbox.getChildren().get(hbox.getChildren().size() - 1);
    ListView<HashFunctionItem> hashFunctionCheckComboBox = (ListView<HashFunctionItem>) hashFunctionNode;

    ObservableList<HashFunctionItem> checkedItems = hashFunctionCheckComboBox.getItems()
        .stream()
        .filter(HashFunctionItem::isChecked)
        .collect(Collectors.toCollection(FXCollections::observableArrayList));

    if (checkedItems.isEmpty()) {
      hashFunctionCheckComboBox.setStyle("-fx-border-color: red;");
      return true;
    } else {
      hashFunctionCheckComboBox.setStyle("-fx-border-color: green;");
      return addHashFunctionSelections(checkedItems, currentGroupHashFunctionSelections,
          groupIndex);
    }
  }

  /**
   * Adds selected hash functions and their configurations to the current group's hash function
   * list.
   *
   * @param checkedItems                       List of selected hash function items.
   * @param currentGroupHashFunctionSelections List to store hash function selections for the
   *                                           current group.
   * @param groupIndex                         Index of the current group.
   * @return True if an invalid input is found, false otherwise.
   */
  private boolean addHashFunctionSelections(List<HashFunctionItem> checkedItems,
      List<HashFunctionSelection> currentGroupHashFunctionSelections, int groupIndex) {
    boolean invalidField = false;
    for (HashFunctionItem item : checkedItems) {
      // Check if the custom size is valid only when the ComboBox selection is "Custom"
      String customSize = item.getCustomHashSize();
      String hashFunctionName = item.getName(); // Retrieve the hash function name
      String comboBoxSelection = item.getComboBoxSelection(); // Retrieve the ComboBox selection
      int[] fractionsArray = new int[2];
      if ("Custom".equals(comboBoxSelection)) {
        fractionsArray = validateFraction(customSize);
        invalidField = (fractionsArray == null);
      }

      boolean isProvablySecure = "Provably Secure".equals(comboBoxSelection);
      DigestType digestType = DigestType.getDigestTypeFromCustomString(hashFunctionName);
      currentGroupHashFunctionSelections.add(
          new HashFunctionSelection(digestType, isProvablySecure, fractionsArray));


    }

    keyConfigToHashFunctionsMap.put(groupIndex,
        new ArrayList<>(currentGroupHashFunctionSelections));
    return invalidField;
  }

  /**
   * Processes key size configuration from the given HBox.
   *
   * @param hbox The HBox containing key size configuration controls.
   * @return True if an invalid input is found, false otherwise.
   */
  private boolean processKeySizeConfiguration(HBox hbox) {
    boolean invalidField = false;
    TextField textField = (TextField) hbox.getChildren().get(0);
    CheckBox checkBox = (CheckBox) hbox.getChildren().get(1);

    textField.setStyle("");

    // Validate the text field input
    String inputText = textField.getText().trim();
    if (!inputText.isEmpty() && inputText.matches(
        "^\\s*(\\d+/\\d+\\s*)(,\\s*\\d+/\\d+\\s*)*$")) {
      String[] fractionStrings = inputText.split(",");
      double totalSum = 0;
      for (String fraction : fractionStrings) {
        String[] parts = fraction.trim().split("/");
        int numerator = Integer.parseInt(parts[0]);
        int denominator = Integer.parseInt(parts[1]);
        totalSum += (double) numerator / denominator;
      }

      if (Math.abs(totalSum - 1.0) > 0.00001) {
        invalidField = true;
        textField.setStyle("-fx-control-inner-background: #FFDDDD;");
      } else {
        boolean checkBoxValue = checkBox.isSelected();
        int[] fractionsArray = new int[fractionStrings.length * 2];
        for (int i = 0; i < fractionStrings.length; i++) {
          String[] parts = fractionStrings[i].trim().split("/");
          fractionsArray[i * 2] = Integer.parseInt(parts[0]);
          fractionsArray[i * 2 + 1] = Integer.parseInt(parts[1]);
        }
        dynamicKeyConfigurationsData.add(new Pair<>(fractionsArray, checkBoxValue));
      }
    } else {
      invalidField = true;
      textField.setStyle("-fx-control-inner-background: #FFDDDD;");
    }
    return invalidField;
  }


}
