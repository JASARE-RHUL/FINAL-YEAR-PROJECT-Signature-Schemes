package uk.msci.project.rsa;

import static uk.msci.project.rsa.HashFunctionSelection.validateFraction;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.StringReader;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;
import java.util.regex.Pattern;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.collections.ListChangeListener;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.scene.control.RadioButton;
import javafx.scene.control.Toggle;
import javafx.stage.Stage;


/**
 * This abstract class is part of the controller component specific to digital signature operations
 * responsible for handling user interactions for the signature process. It also communicates with
 * the Signature Model to perform the actual signature processing logic. This base controller
 * provides common functionalities used in both signature creation and verification.
 */
public abstract class SignatureBaseController {


  /**
   * The model component of the MVC pattern that handles the data and business logic for digital
   * signature creation and verification.
   */
  SignatureModel signatureModel;

  /**
   * The main controller that orchestrates the flow between different views of the application.
   */
  final MainController mainController;

  /**
   * The message to be signed, stored as a byte array.
   */
  private byte[] message;

  /**
   * Represents the file containing a batch of messages for signature processing.
   */
  File messageBatchFile;

  /**
   * Represents the file containing a batch of signatures for signature verification.
   */
  File signatureBatchFile;

  /**
   * raw user entered value for their desired hash output size.
   */
  String hashOutputSize;
  /**
   * Indicates whether cross-parameter benchmarking is enabled in the application. This flag is set
   * to true when the application is operating in a mode that allows comparison of signature
   * processes using different key parameter configurations.
   */
  boolean isCrossParameterBenchmarkingEnabled;

  /**
   * Flag indicating if the current operation is being conducted in comparison mode. This typically
   * involves comparing standard parameter configurations with provably secure ones.
   */
  boolean isKeyForComparisonMode;

  /**
   * Indicates whether the key currently being used is provably secure (small e used to generate the
   * key).
   */
  boolean isKeyProvablySecure;

  /**
   * Holds batch of keys pre-loaded from cross benchmarking mode of the key generation process as a
   * string. This string contains key data used for batch operations in comparison mode. Each key in
   * the batch is typically separated by a newline character.
   */
  String importedKeyBatch;

  /**
   * Indicates whether a single key that has been imported is provably secure. This is relevant in
   * non-benchmarking mode where a single key is used for signature processes.
   */
  boolean isSingleKeyProvablySecure;

  /**
   * Flag indicating whether the import of a key batch was cancelled. This is used to track the
   * state of key batch importation processes and to handle user actions accordingly.
   */
  boolean isKeyBatchImportCancelled;

  /**
   * A list of strings representing key configuration settings. Each string in the list details a
   * specific configuration used in the key generation process.
   */
  List<String> keyConfigurationStrings;

  /**
   * Maps each key configuration group to a list of hash function selections for custom comparison
   * mode. The key is an integer representing the group index, and the value is a list of pairs.
   * Each pair contains a DigestType representing the hash function and a Boolean indicating if the
   * hash function is provably secure.
   */
  Map<Integer, List<HashFunctionSelection>> keyConfigToHashFunctionsMap = new HashMap<>();

  /**
   * Specifies the number of keys per group in a custom cross-parameter benchmarking session. This
   * value determines how many keys are processed together with the same set of hash functions.
   */
  int keysPerGroup = 2;

  /**
   * Flag indicating whether the controller is operating in custom cross-parameter benchmarking
   * mode. When set to true, the controller uses the custom configurations specified in
   * keyConfigToHashFunctionsMap.
   */
  boolean isCustomCrossParameterBenchmarkingMode;

  /**
   * Flag indicating whether the controller is operating in benchmarking mode. When set to true, the
   * controller displays specialised custom hash options.
   */
  boolean isBenchmarkingMode;


  /**
   * Constructs a SignatureBaseController with a reference to the MainController to be used in the
   * event of the user initiating a switch back to main menu.
   *
   * @param mainController The main controller that this controller is part of.
   */
  public SignatureBaseController(MainController mainController) {
    this.mainController = mainController;
  }

  /**
   * Sets up observers common to all modes of  a signature view. This includes observers for
   * benchmarking mode toggle, back to main menu actions, and other common functionalities.
   *
   * @param primaryStage The primary stage of the application where the view will be displayed.
   */
  private void setupCommonToAllObservers(Stage primaryStage, SignatureBaseView signatureView) {
    signatureView.addSignatureSchemeChangeObserver(new SignatureSchemeChangeObserver());
    signatureView.addBenchmarkingModeToggleObserver(new ApplicationModeChangeObserver(
        () -> showStandardMode(primaryStage),
        () -> showBenchmarkingView(primaryStage)
    ));
    signatureView.addBackToMainMenuObserver(new BackToMainMenuObserver(signatureView));
  }

  /**
   * Sets up observers specific to non-cross-benchmarking mode. This includes observers for handling
   * signature scheme changes, parameter choice changes, hash function changes, and provable scheme
   * changes.
   */
  private void setupNonCrossBenchmarkingObservers(SignatureBaseView signatureView) {
    signatureView.addParameterChoiceChangeObserver(
        new ParameterChoiceChangeObserver(signatureView));
    signatureView.addHashFunctionChangeObserver(
        new HashFunctionChangeObserver(signatureView));
    signatureView.addProvableSchemeChangeObserver(
        new ProvableParamsChangeObserver(signatureView));
  }

  /**
   * Sets up observers specific to benchmarking mode. This includes observers for importing text
   * batches, key batches, canceling key batch import, and starting the benchmarking process.
   *
   * @param primaryStage The primary stage of the application where the view will be displayed.
   */
  void setupBenchmarkingObservers(Stage primaryStage, SignatureBaseView signatureView) {
    signatureView.addImportTextBatchBtnObserver(
        new ImportObserver(primaryStage, signatureView, this::handleMessageBatch, "*.txt"));
    signatureView.addImportKeyBatchButtonObserver(
        new ImportObserver(primaryStage, signatureView,
            this::handleKeyBatch, "*.rsa"));
    signatureView.addCancelImportKeyButtonObserver(
        new CancelImportKeyBatchButtonObserver(signatureView));
    signatureView.addCrossParameterToggleObserver(new CrossBenchmarkingModeChangeObserver(
        () -> showCrossBenchmarkingView(primaryStage),
        () -> showBenchmarkingView(primaryStage), signatureView));
  }

  /**
   * Sets up observers for a signature view in the standard (non-benchmarking) mode. This method
   * initialises observers for importing text, keys, canceling imports, creating signatures, and
   * other standard mode functionalities.
   *
   * @param primaryStage The primary stage of the application where the view will be displayed.
   */
  void setupObserversStandardMode(Stage primaryStage, SignatureBaseView signatureView) {
    signatureView.addImportTextObserver(
        new ImportObserver(primaryStage, signatureView,
            this::handleMessageFile, "*.txt"));
    signatureView.addImportKeyObserver(
        new ImportObserver(primaryStage, signatureView,
            this::handleKey, "*.rsa"));
    signatureView.addCancelImportSingleKeyButtonObserver(
        new CancelImportKeyButtonObserver(signatureView));
    signatureView.addCloseNotificationObserver(new BackToMainMenuObserver(signatureView));
    signatureView.addCancelImportTextButtonObserver(
        new CancelImportTextButtonObserver(signatureView));
    setupNonCrossBenchmarkingObservers(signatureView);
    setupCommonToAllObservers(primaryStage, signatureView);

  }

  /**
   * Sets up observers for a signature view in benchmarking mode. This method initialises observers
   * specific to benchmarking, including text batch imports, key batch imports, benchmarking
   * initiation, and additional benchmarking-specific functionalities.
   *
   * @param primaryStage The primary stage of the application where the view will be displayed.
   */
  void setupObserversBenchmarkingMode(Stage primaryStage, SignatureBaseView signatureView) {
    setupCommonToAllObservers(primaryStage, signatureView);
    setupBenchmarkingObservers(primaryStage, signatureView);
    setupNonCrossBenchmarkingObservers(signatureView);
  }

  /**
   * Sets up observers for the SignView in cross-parameter benchmarking mode. This method
   * initialises observers specific to cross-parameter benchmarking, including standard and provable
   * hash function changes, and other functionalities specific to this mode.
   *
   * @param primaryStage The primary stage of the application where the view will be displayed.
   */
  void setupObserversCrossBenchmarking(Stage primaryStage, SignatureBaseView signatureView) {
    setupCommonToAllObservers(primaryStage, signatureView);
    setupBenchmarkingObservers(primaryStage, signatureView);
    signatureView.addStandardHashFunctionChangeObserver(new StandardHashFunctionChangeObserver());
    signatureView.addProvableHashFunctionChangeObserver(new ProvableHashFunctionChangeObserver());
  }

  /**
   * Handles a batch of messages for signature processing. This method is invoked when a file
   * containing multiple messages is imported for either signature creation or verification in
   * benchmarking mode. The implementation of this method should process each message in the batch
   * accordingly.
   *
   * @param file          The file containing a batch of messages.
   * @param signatureView The view associated with this controller.
   */
  abstract void handleMessageBatch(File file, SignatureBaseView signatureView);

  /**
   * Displays the signature view in standard mode. This method should transition the user interface
   * to a state that supports standard signature operations without benchmarking or cross-parameter
   * functionalities.
   *
   * @param primaryStage The primary stage of the application where the view will be displayed.
   */
  abstract void showStandardMode(Stage primaryStage);

  /**
   * Displays the signature view in cross-parameter benchmarking mode. This method should transition
   * the user interface to a state that supports benchmarking of signature operations across
   * different key parameters.
   *
   * @param primaryStage The primary stage of the application where the view will be displayed.
   */
  abstract void showCrossBenchmarkingView(Stage primaryStage);

  /**
   * Displays the signature view in benchmarking mode. This method should transition the user
   * interface to a state that supports benchmarking functionalities for signature operations.
   *
   * @param primaryStage The primary stage of the application where the view will be displayed.
   */
  abstract void showBenchmarkingView(Stage primaryStage);

  /**
   * Preloads a provably secure key into the signature view. This method is used to set up the view
   * with a provably secure key, typically in a standard mode where a single key is generated using
   * a small e is used for the signature process.
   *
   * @param signatureView The signature view to be updated with the preloaded key.
   */
  void preloadProvablySecureKey(SignatureBaseView signatureView) {
    if (isSingleKeyProvablySecure && this.importedKeyBatch != null) {
      updateWithImportedKey(signatureView);
      signatureView.setImportKeyButtonVisibility(false);
      signatureView.setCancelImportSingleKeyButtonVisibility(true);
      signatureView.setProvableParamsHboxVisibility(true);
      signatureView.setProvablySecureParametersRadioSelected(true);
      signatureView.setCustomParametersRadioVisibility(false);
      signatureView.setStandardParametersRadioVisibility(false);
    }
  }

  /**
   * Preloads a batch of provably secure (small e) keys into the signature view. This method is used
   * in benchmarking mode to set up the view with a batch of provably secure keys for batch
   * operations.
   *
   * @param signatureView The signature view to be updated with the preloaded key batch.
   */
  void preloadProvablySecureKeyBatch(SignatureBaseView signatureView) {
    if (isSingleKeyProvablySecure && this.importedKeyBatch != null
        && !isCrossParameterBenchmarkingEnabled) {
      updateWithImportedKeyBatch(signatureView);
      signatureView.setImportKeyBatchButtonVisibility(false);
      signatureView.setCancelImportKeyButtonVisibility(true);
      signatureView.setProvableParamsHboxVisibility(true);
      signatureView.setProvablySecureParametersRadioSelected(true);
      signatureView.setCustomParametersRadioVisibility(false);
      signatureView.setStandardParametersRadioVisibility(false);
    }
  }

  /**
   * Preloads a batch of keys for cross-parameter benchmarking into the signature view. This method
   * sets up the view with a batch of keys that are compatible for cross parameter benchmarking
   * mode.
   *
   * @param signatureView The signature view to be updated with the cross-parameter key batch.
   */
  void preloadCrossParameterKeyBatch(SignatureBaseView signatureView) {
    updateWithImportedKeyBatch(signatureView);
    signatureModel.setNumKeysPerKeySizeComparisonMode(keyConfigurationStrings.size());
    signatureModel.setKeyConfigurationStrings(keyConfigurationStrings);
    if (isCrossParameterBenchmarkingEnabled && this.importedKeyBatch != null) {
      signatureView.setImportKeyBatchButtonVisibility(false);
      signatureView.setCancelImportKeyButtonVisibility(true);
    }
  }

  /**
   * Preloads hash function configurations for custom cross-parameter benchmarking mode. This method
   * is invoked to set up the signature model with the predefined hash function mappings and the
   * number of keys per group for batch processing.
   *
   * @param signatureView The signature view to be updated with hash function configurations.
   */
  void preloadCustomCrossParameterHashFunctions(SignatureBaseView signatureView) {
    if (keyConfigToHashFunctionsMap != null && isCustomCrossParameterBenchmarkingMode) {
      signatureModel.setKeyConfigToHashFunctionsMap(keyConfigToHashFunctionsMap);
      signatureModel.setKeysPerGroup(keysPerGroup);
      signatureView.setProvableHashChoiceComparisonModeHboxVisibility(false);
      signatureView.setStandardHashChoiceComparisonModeHboxVisibility(false);
    } else {
      signatureModel.setKeysPerGroup(2);
    }
  }

  /**
   * Handles the importing of a key file. Validates the key and updates the model and view
   * accordingly. It expects the key file to contain a specific format and updates the view based on
   * the result of the key validation.
   *
   * @param file          The key file selected by the user.
   * @param signatureView The signature view that will be updated based on the imported key.
   */
  public boolean handleKey(File file, SignatureBaseView signatureView) {
    String content = "";
    try {
      content = FileHandle.importFromFile(file);
    } catch (Exception e) {
      uk.msci.project.rsa.DisplayUtility.showErrorAlert("Error importing file, please try again.");
      return false;
    }
    if (!(Pattern.compile("^\\d+,\\d+$").matcher(content).matches())) {
      uk.msci.project.rsa.DisplayUtility.showErrorAlert(
          "Error: Invalid key. Key could not be imported.");
      return false;
    } else {
      resetPreLoadedKeyParams();
      if (signatureView instanceof SignView) {
        signatureModel.setKey(new PrivateKey(content));
      } else {
        signatureModel.setKey(new PublicKey(content));
      }
      signatureView.setKey(file.getName());
      signatureView.setCheckmarkImage();
      signatureView.setCheckmarkImageVisibility(true);
      signatureView.setKeyVisibility(true);

    }
    signatureView.setImportKeyButtonVisibility(false);
    signatureView.setCancelImportSingleKeyButtonVisibility(true);
    return true;
  }


  /**
   * Observer responsible for handling the import of a file. It utilises a file chooser to select a
   * file with a specified extension and then processes it using a provided Consumer.
   */

  class ImportObserver implements EventHandler<ActionEvent> {

    private final Stage stage;
    private final SignatureBaseView signatureView;
    private final BiConsumer<File, SignatureBaseView> fileConsumer;
    private final String fileExtension;

    /**
     * Constructs an observer for importing a file. It uses a file chooser to select a file and then
     * processes it using a provided BiConsumer.
     *
     * @param stage         The primary stage of the application to show the file chooser.
     * @param signatureView The signature view to be updated with the imported asset.
     * @param fileConsumer  The BiConsumer that processes the selected file and updates the view.
     * @param fileExtension The file extension to filter files in the file chooser.
     */
    public ImportObserver(Stage stage, SignatureBaseView signatureView,
        BiConsumer<File, SignatureBaseView> fileConsumer, String fileExtension) {
      this.stage = stage;
      this.signatureView = signatureView;
      this.fileConsumer = fileConsumer;
      this.fileExtension = fileExtension;
    }

    @Override
    public void handle(ActionEvent event) {
      uk.msci.project.rsa.DisplayUtility.handleFileImport(stage, fileExtension,
          file -> fileConsumer.accept(file, signatureView));
    }
  }

  /**
   * The observer for exporting content to a file. This class handles the action event triggered
   * when the user wants to export any kind of textual content. It is responsible for facilitating
   * the file export process by using file handling utilities and displaying relevant alerts to
   * inform the user of the operation's status.
   */
  class ExportObserver implements EventHandler<ActionEvent> {

    private final String filename;
    private final String fileContent;
    private final String infoAlertContent;

    /**
     * Constructs an ExportObserver with the specified file name, content, and alert information.
     * This observer is responsible for exporting the provided content to a file and displaying an
     * informational alert upon successful export.
     *
     * @param filename         The name of the file to which content is to be exported.
     * @param fileContent      The content to be exported to the file.
     * @param infoAlertContent The message to be displayed in an alert upon successful export.
     */
    public ExportObserver(String filename, String fileContent, String infoAlertContent) {
      this.filename = filename;
      this.fileContent = fileContent;
      this.infoAlertContent = infoAlertContent;
    }

    @Override
    public void handle(ActionEvent event) {
      try {
        FileHandle.exportToFile(filename, fileContent);
        uk.msci.project.rsa.DisplayUtility.showInfoAlert("Export", infoAlertContent);
      } catch (Exception e) {
        e.printStackTrace();
      }
    }
  }

  /**
   * The observer for copying content to the clipboard. This class handles the action event
   * triggered when the user wants to copy any textual content to the clipboard. It provides a
   * convenient interface for copying text and displays an error alert in case of a failure.
   */
  class CopyToClipboardObserver implements EventHandler<ActionEvent> {

    private final String contentType;
    private final String content;
    private final String errorAlertContent;

    /**
     * Constructs a CopyToClipboardObserver with specified content type, content, and error alert
     * information. This observer is responsible for copying the provided content to the clipboard
     * and displaying an error alert in case of a failure.
     *
     * @param contentType       The type of content to be copied (e.g., "signature").
     * @param content           The actual content to be copied to the clipboard.
     * @param errorAlertContent The error message to be displayed if the copy operation fails.
     */
    public CopyToClipboardObserver(String contentType, String content, String errorAlertContent) {
      this.contentType = contentType;
      this.content = content;
      this.errorAlertContent = errorAlertContent;
    }

    @Override
    public void handle(ActionEvent event) {
      try {
        uk.msci.project.rsa.DisplayUtility.copyToClipboard(content, contentType);
      } catch (Exception e) {
        uk.msci.project.rsa.DisplayUtility.showErrorAlert(errorAlertContent);
        //"Failed to copy signature to clipboard."
      }
    }
  }

  /**
   * Handles the file selected by the user for the message to be signed or verified. It reads the
   * file contents and updates the view to reflect the text has been loaded. If the file content is
   * empty or does not meet the expected format, an error alert is shown.
   *
   * @param file          The file selected by the user containing the message to sign.
   * @param signatureView The signature view that will be updated based on the imported message.
   */

  public void handleMessageFile(File file, SignatureBaseView signatureView) {
    String content = "";
    try {
      content = FileHandle.importFromFile(file);
    } catch (Exception e) {
      uk.msci.project.rsa.DisplayUtility.showErrorAlert("Error importing file, please try again.");
    }
    if (content == "") {
      uk.msci.project.rsa.DisplayUtility.showErrorAlert(
          file.getName() + " is empty. Please try again.");
    } else {
      this.setMessage(content.getBytes());
      signatureView.setTextInput("");
      signatureView.setTextFileNameLabel(file.getName());
      signatureView.setTextInputVisibility(false);
      signatureView.setCheckmarkImageMessageBatch();
      signatureView.setTextInputHBoxVisibility(true);

      signatureView.setImportTextButtonVisibility(false);
      signatureView.setCancelImportTextButtonVisibility(true);

    }
  }


  /**
   * The observer for changes in signature scheme selection. This class reacts to change in the
   * selected signature scheme and updates the model accordingly. It is responsible for ensuring
   * that the signature model is aware of the currently selected signature scheme, allowing for
   * correct processing of signatures.
   */
  class SignatureSchemeChangeObserver implements ChangeListener<String> {

    /**
     * Responds to change in the selected signature scheme.
     *
     * @param observable The observable value.
     * @param oldValue   The previous value.
     * @param newValue   The new value.
     */
    @Override
    public void changed(ObservableValue<? extends String> observable, String oldValue,
        String newValue) {
      switch (newValue) {
        case "ANSI X9.31 rDSA":
          signatureModel.setSignatureType(SignatureType.ANSI_X9_31_RDSA);
          break;
        case "ISO\\IEC 9796-2 Scheme 1":
          signatureModel.setSignatureType(SignatureType.ISO_IEC_9796_2_SCHEME_1);
          break;
        case "PKCS#1 v1.5":
        default:
          signatureModel.setSignatureType(SignatureType.RSASSA_PKCS1_v1_5);
      }
    }
  }

  /**
   * Observer for changes in hash function selection. Reacts to change in the selected hash function
   * and updates the model accordingly. Ensures that the signature model is set with the correct
   * hash function based on the user selection and trigger the view to display text field prompting
   * the user to enter a hash output size when they select a variable length hash function in custom
   * mode.
   * <p>
   * Otherwise, preset options are used in the case of the standard hash functions which are fixed
   * or the provably secure mode for variable length hash functions which determines hash output
   * half the length of the modulus.
   */
  class HashFunctionChangeObserver implements ChangeListener<String> {

    private SignatureBaseView signatureView;

    public HashFunctionChangeObserver(SignatureBaseView signatureView) {
      this.signatureView = signatureView;
    }

    @Override
    public void changed(ObservableValue<? extends String> observable, String oldValue,
        String newValue) {
      if (newValue == null) {
        return;
      }
      switch (newValue) {
        case "SHAKE-256":
          signatureModel.setHashType(DigestType.SHAKE_256);
          if (signatureView.getParameterChoice().equals("Provably Secure")) {
            signatureModel.setProvablySecure(true);
          } else {
            signatureView.setHashOutputSizeAreaVisibility(true);
          }
          break;
        case "SHAKE-128":
          signatureModel.setHashType(DigestType.SHAKE_128);
          if (signatureView.getParameterChoice().equals("Provably Secure")) {
            signatureModel.setProvablySecure(true);
            signatureView.setHashOutputSizeAreaVisibility(true);
          }
          break;
        case "SHA-512 with MGF1":
          signatureModel.setHashType(DigestType.MGF_1_SHA_512);
          if (signatureView.getParameterChoice().equals("Provably Secure")) {
            signatureModel.setProvablySecure(true);
          } else {
            signatureView.setHashOutputSizeAreaVisibility(true);
          }
          break;
        case "SHA-256 with MGF1":
          signatureModel.setHashType(DigestType.MGF_1_SHA_256);
          if (signatureView.getParameterChoice().equals("Provably Secure")) {
            signatureModel.setProvablySecure(true);
          } else {
            signatureView.setHashOutputSizeAreaVisibility(true);
          }
          break;
        case "SHA-512":
          signatureModel.setHashType(DigestType.SHA_512);
          signatureModel.setProvablySecure(false);
          break;
        case "SHA-256":
        default:
          signatureModel.setHashType(DigestType.SHA_256);
          signatureModel.setProvablySecure(false);
          break;
      }
    }
  }


  /**
   * The observer for changes in parameter choice (standard vs. provably secure vs. custom). This
   * class reacts to change in the selected parameter option and updates the hash function drop down
   * menu immediately below with corresponding option.
   * <p>
   * For example in standard reveals on fixed hash function types while provably secure and custom
   * mode reveal variable length hash function types with the distinction being that customs lets
   * the user choose the output size in an adjacent text box that displayed whereas provably secure
   * sets the output size of the variable length hash function to half the length of the modulus for
   * the submitted key.
   */
  class ParameterChoiceChangeObserver implements ChangeListener<Toggle> {

    private SignatureBaseView signatureView;

    public ParameterChoiceChangeObserver(SignatureBaseView signatureView) {
      this.signatureView = signatureView;
    }

    @Override
    public void changed(ObservableValue<? extends Toggle> observable, Toggle oldValue,
        Toggle newValue) {
      signatureView.setSelectedHashFunction("");
      if (newValue != null) {
        RadioButton selectedRadioButton = (RadioButton) newValue;
        String radioButtonText = selectedRadioButton.getText();
        switch (radioButtonText) {
          case "Provably Secure":
            signatureView.setHashOutputSizeAreaVisibility(false);
            signatureView.updateHashFunctionDropdownForCustomOrProvablySecure();
            break;
          case "Custom":
            signatureView.updateHashFunctionDropdownForCustomOrProvablySecure();
            break;
          case "Standard":
          default:
            signatureView.setHashOutputSizeAreaVisibility(false);
            signatureView.updateHashFunctionDropdownForStandard();
            break;

        }
      }
    }
  }


  /**
   * The {@code ApplicationModeChangeObserver} class is an observer for changes in application mode,
   * specifically for toggling between standard and benchmarking modes in signature-related views.
   * This class observes for changes in a Boolean property (tied to a toggle switch UI element) and
   * performs actions based on the mode switch. It uses two {@code Runnable} objects to define the
   * actions to be executed when switching between standard and benchmarking modes.
   * <p>
   * This observer provides flexibility and re-usability for different views where such mode
   * switching functionality is required.
   */
  class ApplicationModeChangeObserver implements ChangeListener<Boolean> {

    private final Runnable onStandardMode;
    private final Runnable onBenchmarkingMode;

    /**
     * Constructs an ApplicationModeChangeObserver with specified actions for standard and
     * benchmarking modes.
     *
     * @param onStandardMode     The action to perform when switching to standard mode.
     * @param onBenchmarkingMode The action to perform when switching to benchmarking mode.
     */
    public ApplicationModeChangeObserver(Runnable onStandardMode, Runnable onBenchmarkingMode) {
      this.onStandardMode = onStandardMode;
      this.onBenchmarkingMode = onBenchmarkingMode;
    }

    @Override
    public void changed(ObservableValue<? extends Boolean> observableValue, Boolean oldValue,
        Boolean newValue) {
      if (Boolean.TRUE.equals(newValue) && Boolean.FALSE.equals(oldValue)) {
        // Switched to Benchmarking Mode
        onBenchmarkingMode.run();
      } else if (Boolean.FALSE.equals(newValue) && Boolean.TRUE.equals(oldValue)) {
        // Switched to Standard Mode
        onStandardMode.run();
      }
    }
  }


  /**
   * Observer for canceling the import of a message in non benchmarking mode. Handles the event when
   * the user decides to cancel the import of the message by replacing the cancel button with the
   * original import button and resetting corresponding text field that display the name of the
   * file.
   */
  class CancelImportTextButtonObserver implements EventHandler<ActionEvent> {

    private SignatureBaseView signatureView;

    public CancelImportTextButtonObserver(SignatureBaseView signatureView) {
      this.signatureView = signatureView;
    }

    @Override
    public void handle(ActionEvent event) {
      signatureView.setTextFileNameLabel("");
      signatureView.setTextInputVisibility(true);
      signatureView.setTextInputHBoxVisibility(false);
      signatureView.setCancelImportTextButtonVisibility(false);
      signatureView.setImportTextButtonVisibility(true);

    }
  }

  /**
   * Sets the message to be signed or verified. This method is used to update the message that will
   * be signed or verified by the signature model.
   *
   * @param message The message to be signed, represented as a byte array.
   */
  public void setMessage(byte[] message) {
    this.message = message;
  }


  /**
   * The observer for returning to the main menu. This class handles the action event triggered when
   * the user wishes to return to the main menu from the signature view.
   */
  class BackToMainMenuObserver implements EventHandler<ActionEvent> {

    private SignatureBaseView signatureView;

    public BackToMainMenuObserver(SignatureBaseView viewInterface) {
      this.signatureView = viewInterface;
    }

    @Override
    public void handle(ActionEvent event) {
      mainController.showMainMenuView();
      signatureView = null;
      signatureModel = null;
    }

  }

  /**
   * Observer for canceling the import of a key batch. Handles the event when the user decides to
   * cancel the import of a batch of keys.
   */
  class CancelImportKeyBatchButtonObserver implements EventHandler<ActionEvent> {

    private SignatureBaseView signatureView;

    public CancelImportKeyBatchButtonObserver(SignatureBaseView signatureView) {
      this.signatureView = signatureView;
    }

    @Override
    public void handle(ActionEvent event) {
      resetPreLoadedKeyParams();
      signatureView.setProvableParamsHboxVisibility(false);
      signatureView.setCustomParametersRadioVisibility(true);
      signatureView.setStandardParametersRadioVisibility(true);
      isKeyBatchImportCancelled = true;
      signatureView.setSelectedCrossParameterToggleObserver(false);
      signatureView.setCheckmarkImageVisibility(false);
      if (signatureView instanceof SignView) {
        signatureView.setKey("Please Import a private key batch");
      } else {
        signatureView.setKey("Please Import a public key batch");
      }
      signatureModel.clearPrivateKeyBatch();
      signatureModel.clearPublicKeyBatch();
      signatureView.setCancelImportKeyButtonVisibility(false);
      signatureView.setImportKeyBatchButtonVisibility(true);

    }
  }

  /**
   * Observer for canceling the import of a key. Handles the event when the user decides to cancel
   * the import of a key in non-benchmarking mode.
   */
  class CancelImportKeyButtonObserver implements EventHandler<ActionEvent> {

    private SignatureBaseView signatureView;

    public CancelImportKeyButtonObserver(SignatureBaseView signatureView) {
      this.signatureView = signatureView;
    }

    @Override
    public void handle(ActionEvent event) {
      resetPreLoadedKeyParams();
      signatureView.setCustomParametersRadioVisibility(true);
      signatureView.setStandardParametersRadioVisibility(true);
      signatureView.setSelectedCrossParameterToggleObserver(false);
      signatureView.setProvableParamsHboxVisibility(false);
      signatureView.setCheckmarkImageVisibility(false);
      if (signatureView instanceof SignView) {
        signatureView.setKey("Please Import a private key");
      } else {
        signatureView.setKey("Please Import a public key");
      }
      signatureView.setCancelImportSingleKeyButtonVisibility(false);
      signatureView.setImportKeyButtonVisibility(true);

    }
  }

  /**
   * Handles the file selected by the user for a batch of keys. It validates the keys and updates
   * the model and view accordingly. It expects the key file to contain a line separated text of
   * comma delimited positive integers and updates the view based on the result of the key
   * validation.
   *
   * @param file          The file selected by the user containing a batch of keys.
   * @param signatureView The signature view that will be updated based on the imported key batch.
   */
  public boolean handleKeyBatch(File file, SignatureBaseView signatureView) {
    try (BufferedReader keyReader = new BufferedReader(new FileReader(file))) {
      String keyContent;
      while ((keyContent = keyReader.readLine()) != null) {
        if (!(Pattern.compile("^\\s*\\d+\\s*(,\\s*\\d+\\s*)*$").matcher(keyContent)
            .matches())) {
          uk.msci.project.rsa.DisplayUtility.showErrorAlert(
              "Invalid key batch. Please make sure the file contains a contiguous sequence of new line separated and valid keys.");
          return false;
        } else {
          resetPreLoadedKeyParams();
          if (this instanceof SignatureCreationController) {
            signatureModel.addPrivKeyToBatch(keyContent);
          } else {
            signatureModel.addPublicKeyToBatch(keyContent);
          }
          signatureView.setKey(file.getName());
          signatureView.setCheckmarkImage();
          signatureView.setCheckmarkImageVisibility(true);
          signatureView.setKeyVisibility(true);
        }
      }

    } catch (Exception e) {
      uk.msci.project.rsa.DisplayUtility.showErrorAlert(
          "Invalid key batch. Please make sure the file contains new line separated contiguous sequence of valid keys.");
      return false;
    }

    signatureView.setImportKeyBatchButtonVisibility(false);
    signatureView.setCancelImportKeyButtonVisibility(true);
    return true;
  }

  /**
   * Checks a file for non-empty lines and counts the number of valid lines. This method is used to
   * validate message or signature batch files to ensure they meet the expected format.
   *
   * @param file     The file to be checked.
   * @param artefact A string describing the artefact being checked (e.g., "message", "signature").
   * @return The number of non-empty lines if the file is valid, otherwise 0.
   */
  public int checkFileForNonEmptyLines(File file, String artefact) {
    boolean encounteredNonEmptyLine = false;
    boolean isValidFile = true;
    int numMessages = 0;

    try (BufferedReader messageReader = new BufferedReader(new FileReader(file))) {
      String messageString;
      while ((messageString = messageReader.readLine()) != null) {
        if (!messageString.isEmpty()) {
          encounteredNonEmptyLine = true;
          numMessages++;
        } else if (encounteredNonEmptyLine) {
          // Encountered an empty line after a non-empty line
          uk.msci.project.rsa.DisplayUtility.showErrorAlert(
              "Invalid " + artefact + " batch. Please make sure the file contains no empty lines.");
          isValidFile = false;
          break;
        }
      }
    } catch (IOException e) {
      uk.msci.project.rsa.DisplayUtility.showErrorAlert("Error reading file: " + e.getMessage());
      isValidFile = false;
    }

    if (!isValidFile) {
      uk.msci.project.rsa.DisplayUtility.showErrorAlert(
          "Invalid " + artefact
              + " batch. Please make sure the file contains a contiguous sequence of new line separated messages that matches the number entered in the the above field.");
    }

    return isValidFile ? numMessages : 0;
  }


  /**
   * Updates the signature model and view with an imported key. This method is used to update the
   * model with the key content and to update the view to reflect that a key has been imported. It
   * processes the imported key batch line by line to add keys to the signature model.
   *
   * @param signatureView The signature view to be updated with the imported key batch.
   */
  public void updateWithImportedKeyBatch(SignatureBaseView signatureView) {
    try (BufferedReader reader = new BufferedReader(new StringReader(this.importedKeyBatch))) {
      String keyContent;
      while ((keyContent = reader.readLine()) != null) {
        if (this instanceof SignatureCreationController) {
          signatureModel.addPrivKeyToBatch(keyContent);
        } else {
          signatureModel.addPublicKeyToBatch(keyContent);
        }
      }
    } catch (IOException e) {
      e.printStackTrace();
    }
    if (signatureView.isBenchmarkingModeEnabled()) {
      if (isCrossParameterBenchmarkingEnabled) {
        signatureView.setKey("Keys were loaded for cross-parameter comparison");
      } else {
        signatureView.setKey("A provably-secure key batch was loaded");
      }

    } else {
      signatureView.setKey("A provably-secure key was loaded");
    }
    signatureView.setCheckmarkImage();
    signatureView.setCheckmarkImageVisibility(true);
    signatureView.setKeyVisibility(true);
  }

  /**
   * Updates the signature model and view with an imported key. This method is used to update the
   * model with the key content and to update the view to reflect that a key has been imported in
   * non benchmarking mode.
   *
   * @param signatureView The signature view to be updated with the imported key.
   */
  public void updateWithImportedKey(SignatureBaseView signatureView) {
    if (this instanceof SignatureCreationController) {
      signatureModel.setKey(new PrivateKey(importedKeyBatch));
    } else {
      signatureModel.setKey(new PublicKey(importedKeyBatch));
    }

    signatureView.setKey("A provably-secure key was loaded");
    signatureView.setCheckmarkImage();
    signatureView.setCheckmarkImageVisibility(true);
    signatureView.setKeyVisibility(true);
  }

  /**
   * Observer for changes in the Cross Benchmarking Mode. This observer handles the toggle event
   * between enabling and disabling cross benchmarking mode. It launches an FXML file with
   * specialised cross-parameter benchmarking options when the toggle is switched on and does not
   * allow a user to switch the toggle on, unless a key in the format expected for the mode and been
   * pre-loaded implicitly through the prior key generation process where the option was selected.
   */
  class CrossBenchmarkingModeChangeObserver implements ChangeListener<Boolean> {

    private SignatureBaseView signatureView;
    private final Runnable onCrossBenchmarkingMode;
    private final Runnable onBenchmarkingMode;


    /**
     * Constructs an CrossBenchmarkingModeChangeObserver with specified actions for cross
     * benchmarking and benchmarking modes.
     *
     * @param onCrossBenchmarkingMode The action to perform when switching to Cross Benchmarking
     *                                mode.
     * @param onBenchmarkingMode      The action to perform when switching to benchmarking mode.
     */
    public CrossBenchmarkingModeChangeObserver(Runnable onCrossBenchmarkingMode,
        Runnable onBenchmarkingMode, SignatureBaseView signatureView) {
      this.onCrossBenchmarkingMode = onCrossBenchmarkingMode;
      this.onBenchmarkingMode = onBenchmarkingMode;
      this.signatureView = signatureView;
    }

    @Override
    public void changed(ObservableValue<? extends Boolean> observableValue, Boolean oldValue,
        Boolean newValue) {
      if (Boolean.TRUE.equals(newValue) && Boolean.FALSE.equals(oldValue)) {
        if ((!isCrossParameterBenchmarkingEnabled && importedKeyBatch == null)
            || !isKeyForComparisonMode) {
          signatureView.setSelectedCrossParameterToggleObserver(false);
          uk.msci.project.rsa.DisplayUtility.showErrorAlert(
              "Cross parameter benchmarking cannot be enabled without an initial cross parameter generation of keys.");
        } else {
          isCrossParameterBenchmarkingEnabled = true;
          onCrossBenchmarkingMode.run();
        }
      } else if (Boolean.FALSE.equals(newValue) && Boolean.TRUE.equals(oldValue)) {
        if (isCrossParameterBenchmarkingEnabled || isKeyBatchImportCancelled) {
          isKeyBatchImportCancelled = false;
          isCrossParameterBenchmarkingEnabled = false;
          onBenchmarkingMode.run();
        }
      }
    }
  }

  /**
   * Observer for changes in the selection of standard hash functions in cross-parameter
   * benchmarking mode. Reacts to the addition or removal of hash function choices in the UI and
   * updates the signature model to reflect these changes for standard (non-provably secure) hash
   * functions.
   */
  class ProvableParamsChangeObserver implements ChangeListener<Toggle> {

    private SignatureBaseView signatureView;

    public ProvableParamsChangeObserver(SignatureBaseView signatureView) {
      this.signatureView = signatureView;
    }

    @Override
    public void changed(ObservableValue<? extends Toggle> observable, Toggle oldValue,
        Toggle newValue) {
      if (newValue != null) {
        RadioButton selectedRadioButton = (RadioButton) newValue;
        String radioButtonText = selectedRadioButton.getText();
        switch (radioButtonText) {
          case "Yes":
            if (isKeyProvablySecure || isSingleKeyProvablySecure) {
              signatureView.setProvablySecureParametersRadioSelected(true);
              signatureView.setCustomParametersRadioVisibility(false);
              signatureView.setStandardParametersRadioVisibility(false);
            }
            break;
          case "No":
          default:
            signatureView.setProvablySecureParametersRadioSelected(false);
            signatureView.setCustomParametersRadioVisibility(true);
            signatureView.setStandardParametersRadioVisibility(true);
            break;

        }
      }
    }
  }

  /**
   * Observer for changes in the selection of provably secure hash functions in cross-parameter
   * benchmarking mode. Handles the addition or removal of provably secure hash function choices in
   * the UI and updates the signature model accordingly.
   */
  class ProvableHashFunctionChangeObserver implements ListChangeListener<String> {

    @Override
    public void onChanged(ListChangeListener.Change<? extends String> c) {
      while (c.next()) {
        if (c.wasAdded()) {
          for (String addedType : c.getAddedSubList()) {
            signatureModel.getCurrentProvableHashTypeList_ComparisonMode()
                .add(new HashFunctionSelection(DigestType.getDigestTypeFromCustomString(addedType),
                    true, null));
          }
        } else if (c.wasRemoved()) {
          for (String removedType : c.getRemoved()) {
            signatureModel.getCurrentProvableHashTypeList_ComparisonMode()
                .remove((new HashFunctionSelection(
                    DigestType.getDigestTypeFromCustomString(removedType), true, null)));
          }
        }

      }
    }

  }

  /**
   * Observer for changes in the selection of standard hash function. This observer responds to
   * change in hash function selection when in cross parameter benchmarking mode and updates the
   * signature model accordingly. It sets...
   */
  class StandardHashFunctionChangeObserver implements ListChangeListener<String> {

    @Override
    public void onChanged(ListChangeListener.Change<? extends String> c) {
      while (c.next()) {
        if (c.wasAdded()) {
          for (String addedType : c.getAddedSubList()) {
            signatureModel.getCurrentFixedHashTypeList_ComparisonMode()
                .add((new HashFunctionSelection(DigestType.getDigestTypeFromCustomString(addedType),
                    false, null)));
          }
        } else if (c.wasRemoved()) {
          for (String removedType : c.getRemoved()) {
            signatureModel.getCurrentFixedHashTypeList_ComparisonMode()
                .remove((new HashFunctionSelection(
                    DigestType.getDigestTypeFromCustomString(removedType), false, null)));
          }
        }

      }
    }
  }

  /**
   * Imports a key from the key generation process. This method sets the state of the controller to
   * reflect that a key has been imported for comparison mode or provably secure mode, based on the
   * provided parameters. It updates the internal state with the imported key batch.
   *
   * @param keyBatch               The batch of keys generated and to be imported.
   * @param isKeyForComparisonMode Indicates if the key is for comparison mode.
   */
  public void importKeyFromKeyGeneration(String keyBatch, boolean isKeyForComparisonMode) {

    this.isKeyProvablySecure = !isKeyForComparisonMode;
    this.isCrossParameterBenchmarkingEnabled = isKeyForComparisonMode;
    this.isKeyForComparisonMode = isKeyForComparisonMode;
    importedKeyBatch = keyBatch;

  }

  /**
   * Imports a key from the key generation process. This method sets the state of the controller to
   * reflect that a key has been imported for instantiating a scheme with provably secure in non
   * benchmarking mode. It updates the internal state with the imported key batch.
   *
   * @param key The key generated and to be imported.
   */
  public void importSingleKeyFromKeyGeneration(String key) {
    this.isSingleKeyProvablySecure = true;
    importedKeyBatch = key;
  }

  /**
   * Sets the hash size in the signature model based on the hash output size specified by the user.
   * This method is invoked when there is a need to update the model with the hash size, especially
   * when using variable length hash functions in custom mode. It validates the hash output size
   * entered by the user to ensure it is a non-negative integer and falls within the acceptable
   * range. If the validation fails or if the hash output size field is not visible (not required
   * for the selected hash function), the method will not update the model and will return false.
   * This method is crucial for maintaining the consistency of the signature model state with the
   * user's input on the view.
   * <p>
   *
   * @param signatureView The signature view that provides context for hash size setting.
   * @return Boolean value indicating if validation failed.
   */
  boolean setHashSizeInModelBenchmarking(SignatureBaseView signatureView) {
    if (signatureView.getHashOutputSizeAreaVisibility()) {
      if (!handleHashOutputSizeBenchmarking()) {
        return false;
      }
    }
    return true;
  }


  /**
   * Sets the hash size in the signature model based on the hash output size specified by the user.
   * This method is invoked when there is a need to update the model with the hash size, especially
   * when using variable length hash functions in custom mode. It validates the hash output size
   * entered by the user to ensure it is a non-negative integer and falls within the acceptable
   * range. If the validation fails or if the hash output size field is not visible (not required
   * for the selected hash function), the method will not update the model and will return false.
   * This method is crucial for maintaining the consistency of the signature model state with the
   * user's input on the view.
   * <p>
   *
   * @param signatureView The signature view that provides context for hash size setting.
   * @return Boolean value indicating if validation failed.
   */
  boolean setHashSizeInModel(SignatureBaseView signatureView) {
    if (!handleHashOutputSize(signatureView) && signatureView.getHashOutputSizeAreaVisibility()) {
      return false;
    } else if (signatureView.getHashOutputSizeAreaVisibility()) {
      signatureModel.setHashSize((Integer.parseInt(hashOutputSize) + 7) / 8);
    }
    return true;
  }


  /**
   * Validates the hash output size input by the user. Ensures that it is a non-negative integer and
   * that it is provided when required based on the view's visibility settings.
   *
   * @return true if the hash output size is valid, false otherwise.
   */
  public boolean handleHashOutputSize(SignatureBaseView signatureView) {
    try {
      if (Integer.parseInt(hashOutputSize) < 0
          && signatureView.getHashOutputSizeAreaVisibility()) {
        uk.msci.project.rsa.DisplayUtility.showErrorAlert(
            "You must provide a non-negative integer for the hash output size. Please try again.");
        return false;
      }
    } catch (NumberFormatException e) {
      // Show an error alert if the input is not a valid integer
      if (signatureView.getHashOutputSizeAreaVisibility()) {
        uk.msci.project.rsa.DisplayUtility.showErrorAlert(
            "You must provide a non-negative integer for the hash output size. Please try again.");
      }
      return false;

    }
    return true;
  }

  /**
   * Handles the input for custom hash output size configuration. This method validates the user
   * input to ensure it matches a fraction format (e.g., "1/2") and verifies that the numerator is
   * less than the denominator. The fraction is used to determine the proportion of the modulus size
   * for the hash output in signature operations in benchmarking mode.
   * <p>
   * The method updates the model with the calculated fraction if the input is valid. If the input
   * is invalid, an error alert is displayed to the user, requesting them to provide a valid
   * fraction.
   *
   * @return {@code true} if the hash output size input is valid and successfully processed, {@code
   * false} otherwise.
   */
  public boolean handleHashOutputSizeBenchmarking() {
    boolean invalidField = false;
    int[] fractionsArray = validateFraction(hashOutputSize);

    if (fractionsArray == null) {
      invalidField = true;
      uk.msci.project.rsa.DisplayUtility.showErrorAlert(
          "Please enter a valid fraction representing the desired proportion of the modulus size for the hash output. Try again.");
    } else {
      signatureModel.setCustomHashSizeFraction(fractionsArray);
    }

    return !invalidField;
  }


  /**
   * Resets the parameters related to pre-loaded keys in the signature processes. This method is
   * used to reset the internal state of the controller, specifically the flags and data related to
   * cross-parameter benchmarking, comparison mode, and provably secure keys. It ensures that the
   * controller's state accurately reflects the absence of pre-loaded keys, particularly after the
   * completion of a benchmarking process or when switching contexts.
   */
  void resetPreLoadedKeyParams() {
    isCrossParameterBenchmarkingEnabled = false;
    isCustomCrossParameterBenchmarkingMode = false;
    keyConfigToHashFunctionsMap = null;
    keysPerGroup = 2;
    this.isKeyForComparisonMode = false;
    this.importedKeyBatch = null;
    this.isKeyProvablySecure = false;
    isSingleKeyProvablySecure = false;
  }

  /**
   * An indication of whether there is single key that has been pre-loaded for the signature
   * creation process in non benchmarking mode.
   */
  public boolean getIsSingleKeyProvablySecure() {
    return isSingleKeyProvablySecure;
  }

  /**
   * Sets the list of key configuration strings corresponding to settings used to generate the
   * various keys for each key size selected by the user in the key generation process.
   *
   * @param keyConfigurationStrings A list of key configuration strings.
   */
  public void setKeyConfigurationStrings(List<String> keyConfigurationStrings) {
    this.keyConfigurationStrings = keyConfigurationStrings;
  }

  /**
   * Sets the mapping of key configurations to hash functions for custom comparison benchmarking
   * mode. This method updates the controller's state with the specified mapping and the number of
   * keys per group, enabling detailed comparative analysis of signature processes under various
   * cryptographic conditions.
   *
   * @param keyConfigToHashFunctionsMap The mapping of key configurations to their respective hash
   *                                    functions.
   * @param keysPerGroup                The number of keys in each group for batch processing.
   */
  public void setKeyConfigToHashFunctionsMap(
      Map<Integer, List<HashFunctionSelection>> keyConfigToHashFunctionsMap, int keysPerGroup) {
    this.keyConfigToHashFunctionsMap = keyConfigToHashFunctionsMap;
    this.keysPerGroup = keysPerGroup;
  }

  /**
   * Sets the flag to indicate whether the controller is operating in custom cross-parameter
   * benchmarking mode. When this mode is enabled, the controller uses the custom hash function
   * mappings and key configurations specified for detailed comparison.
   *
   * @param isCustomCrossParameterBenchmarkingMode Flag indicating the custom cross-parameter
   *                                               benchmarking mode.
   */
  public void setIsCustomCrossParameterBenchmarkingMode(
      boolean isCustomCrossParameterBenchmarkingMode) {
    this.isCustomCrossParameterBenchmarkingMode = isCustomCrossParameterBenchmarkingMode;
  }
}
