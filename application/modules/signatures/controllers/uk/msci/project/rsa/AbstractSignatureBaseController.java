package uk.msci.project.rsa;

import java.io.File;
import java.util.regex.Pattern;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
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
public abstract class AbstractSignatureBaseController {

  /**
   * Holds batch of keys preloaded from cross benchmarking mode of the key generation process as a
   * string. This string contains key data used for batch operations in comparison mode. Each key in
   * the batch is typically separated by a newline character.
   */
  String importedKeyBatch;


  /**
   * Flag indicating whether the controller is operating in benchmarking mode. When set to true, the
   * controller displays specialised custom hash options.
   */
  boolean isBenchmarkingMode;


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
  byte[] message;


  /**
   * raw user entered value for their desired hash output size.
   */
  String hashOutputSize;


  /**
   * Indicates whether the key currently being used is provably secure (small e used to generate the
   * key).
   */
  boolean isKeyProvablySecure;


  /**
   * Indicates whether a single key that has been imported is provably secure. This is relevant in
   * non-benchmarking mode where a single key is used for signature processes.
   */
  boolean isSingleKeyProvablySecure;


  /**
   * Constructs a SignatureBaseController with a reference to the MainController to be used in the
   * event of the user initiating a switch back to main menu.
   *
   * @param mainController The main controller that this controller is part of.
   */
  public AbstractSignatureBaseController(MainController mainController) {
    this.mainController = mainController;
  }

  /**
   * Sets up common observers for all signature views. This includes observers for toggling
   * benchmarking mode, returning to the main menu, and other shared functionalities across
   * different signature operation modes.
   *
   * @param primaryStage   The primary stage of the application where the view is displayed.
   * @param signatureView  The signature view for which observers are being set up.
   * @param signatureModel The signature model associated with the signature view.
   */
  void setupCommonToAllObservers(Stage primaryStage, SignatureBaseView signatureView,
      SignatureModel signatureModel) {
    signatureView.addSignatureSchemeChangeObserver(
        new SignatureSchemeChangeObserver(signatureModel));
    signatureView.addBackToMainMenuObserver(new BackToMainMenuObserver(signatureView));
    signatureView.addBenchmarkingModeToggleObserver(
        new ApplicationModeChangeObserver(AbstractSignatureBaseController.this));
  }

  /**
   * Sets up observers specific to the standard signature operation mode (non-cross-benchmarking).
   * These observers handle events related to signature scheme changes, parameter choice changes,
   * hash function selection, and provable scheme changes.
   *
   * @param signatureView  The signature view for which observers are being set up.
   * @param signatureModel The signature model associated with the signature view.
   */
  void setupNonCrossBenchmarkingObservers(SignatureBaseView signatureView,
      SignatureModel signatureModel) {
    signatureView.addParameterChoiceChangeObserver(
        new ParameterChoiceChangeObserver(signatureView));
    signatureView.addHashFunctionChangeObserver(
        new HashFunctionChangeObserver(signatureView, signatureModel));

  }


  /**
   * Initializes observers for a signature view operating in standard mode (non-benchmarking). This
   * includes observers for importing text and keys, handling cancel operations, and other standard
   * mode specific functionalities.
   *
   * @param primaryStage   The primary stage of the application where the view is displayed.
   * @param signatureView  The signature view for which observers are being set up.
   * @param signatureModel The signature model associated with the signature view.
   */
  void setupObserversStandardMode(Stage primaryStage, SignatureBaseView signatureView,
      SignatureModel signatureModel) {
    signatureView.addImportTextObserver(
        new ImportObserver(primaryStage, signatureView, signatureModel,
            this::handleMessageFile, "*.txt"));
    signatureView.addImportKeyObserver(
        new ImportObserver(primaryStage, signatureView, signatureModel,
            this::handleKey, "*.rsa"));
    signatureView.addCancelImportSingleKeyButtonObserver(
        new CancelImportKeyButtonObserver(signatureView));
    signatureView.addCloseNotificationObserver(new BackToMainMenuObserver(signatureView));
    signatureView.addCancelImportTextButtonObserver(
        new CancelImportTextButtonObserver(signatureView));
    setupNonCrossBenchmarkingObservers(signatureView, signatureModel);
    setupCommonToAllObservers(primaryStage, signatureView, signatureModel);

  }


  /**
   * Preloads a provably secure key into the signature view. This method is used to set up the view
   * with a provably secure key, typically in a standard mode where a single key is generated using
   * a small e is used for the signature process.
   *
   * @param signatureView The signature view to be updated with the preloaded key.
   */
  void preloadProvablySecureKey(SignatureBaseView signatureView) {
    if (isSingleKeyProvablySecure) {
      updateWithImportedKey(signatureView);
      signatureView.setImportKeyButtonVisibility(false);
      signatureView.setCancelImportSingleKeyButtonVisibility(true);
      signatureView.setProvableParamsHboxVisibility(true);
      signatureView.setProvablySecureParametersRadioSelected(true);
      signatureView.setCustomParametersRadioVisibility(false);
      signatureView.setStandardParametersRadioVisibility(false);
      signatureView.addProvableSchemeChangeObserver(new ProvableParamsChangeObserver(signatureView));
    }
  }


  /**
   * Processes a key file imported by the user. Validates the key format and updates the signature
   * model and view based on the result of the validation.
   *
   * @param file           The key file selected by the user.
   * @param signatureView  The signature view to be updated based on the imported key.
   * @param signatureModel The signature model to be updated with the imported key.
   * @return true if the key is valid and imported successfully, false otherwise.
   */
  public boolean handleKey(File file, SignatureBaseView signatureView,
      SignatureModel signatureModel) {
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
   * Functional interface for a consumer that accepts three arguments.
   *
   * @param <T> The type of the first argument.
   * @param <U> The type of the second argument.
   * @param <V> The type of the third argument.
   */
  @FunctionalInterface
  public interface TriConsumer<T, U, V> {

    void accept(T t, U u, V v);
  }


  /**
   * Observer responsible for handling the import of a file. It utilises a file chooser to select a
   * file with a specified extension and then processes it using a provided Consumer.
   */

  class ImportObserver implements EventHandler<ActionEvent> {

    private final Stage stage;
    private final SignatureBaseView signatureView;
    private final SignatureModel signatureModel;
    private final TriConsumer<File, SignatureBaseView, SignatureModel> fileConsumer;
    private final String fileExtension;

    /**
     * Constructs an observer for importing a file. It uses a file chooser to select a file and then
     * processes it using a provided BiConsumer.
     *
     * @param stage          The primary stage of the application to show the file chooser.
     * @param signatureView  The signature view to be updated with the imported asset.
     * @param signatureModel The signature model associated with the view.
     * @param fileConsumer   The TriConsumer that processes the selected file and updates the view.
     * @param fileExtension  The file extension to filter files in the file chooser.
     */
    public ImportObserver(Stage stage, SignatureBaseView signatureView,
        SignatureModel signatureModel,
        TriConsumer<File, SignatureBaseView, SignatureModel> fileConsumer,
        String fileExtension) {
      this.stage = stage;
      this.signatureView = signatureView;
      this.signatureModel = signatureModel;
      this.fileConsumer = fileConsumer;
      this.fileExtension = fileExtension;
    }

    @Override
    public void handle(ActionEvent event) {
      uk.msci.project.rsa.DisplayUtility.handleFileImport(stage, fileExtension,
          file -> fileConsumer.accept(file, signatureView, signatureModel));
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
   * Handles the selection of a message file by the user. Reads the file content and updates the
   * signature view to display the imported message. If the file content is invalid or empty, an
   * error alert is shown.
   *
   * @param file           The file containing the message to be signed or verified.
   * @param signatureView  The signature view to be updated with the imported message.
   * @param signatureModel The signature model associated with the signature view.
   */
  public void handleMessageFile(File file, SignatureBaseView signatureView,
      SignatureModel signatureModel) {
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

    private SignatureModel signatureModel;

    public SignatureSchemeChangeObserver(SignatureModel signatureModel) {
      this.signatureModel = signatureModel;
    }

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
    private SignatureModel signatureModel;

    public HashFunctionChangeObserver(SignatureBaseView signatureView,
        SignatureModel signatureModel) {
      this.signatureView = signatureView;
      this.signatureModel = signatureModel;
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
          setProvablySecureHashFunction(signatureView, signatureModel);
          break;
        case "SHAKE-128":
          signatureModel.setHashType(DigestType.SHAKE_128);
          setProvablySecureHashFunction(signatureView, signatureModel);
          break;
        case "SHA-512 with MGF1":
          signatureModel.setHashType(DigestType.MGF_1_SHA_512);
          setProvablySecureHashFunction(signatureView, signatureModel);
          break;
        case "SHA-256 with MGF1":
          signatureModel.setHashType(DigestType.MGF_1_SHA_256);
          setProvablySecureHashFunction(signatureView, signatureModel);
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
   * Configures the signature model to use a provably secure hash function based on user selection
   * in the signature view. If the user chooses a variable length hash function in custom mode,
   * prompts for the desired hash output size. Otherwise, sets the hash function based on predefined
   * options for standard and provably secure modes.
   *
   * @param signatureView  The signature view providing the UI context for hash function
   *                       configuration.
   * @param signatureModel The signature model to be configured with the hash function.
   */
  public void setProvablySecureHashFunction(SignatureBaseView signatureView,
      SignatureModel signatureModel) {
    if (signatureView.getParameterChoice().equals("Provably Secure")) {
      signatureModel.setProvablySecure(true);
    } else {
      signatureView.setHashOutputSizeAreaVisibility(true);
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

    private final AbstractSignatureBaseController signatureBaseController;

    public ApplicationModeChangeObserver(AbstractSignatureBaseController signatureBaseController) {
      this.signatureBaseController = signatureBaseController;
    }

    @Override
    public void changed(ObservableValue<? extends Boolean> observableValue, Boolean oldValue,
        Boolean newValue) {
      if (Boolean.TRUE.equals(newValue) && Boolean.FALSE.equals(oldValue)) {
        // Switch to Benchmarking Mode
        signatureBaseController.showBenchmarkingView(mainController.getPrimaryStage());
      } else if (Boolean.FALSE.equals(newValue) && Boolean.TRUE.equals(oldValue)) {
        // Switch to Standard Mode
        signatureBaseController.showStandardMode(mainController.getPrimaryStage());

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
   * Updates the signature model and view with an imported key. This method is used to update the
   * model with the key content and to update the view to reflect that a key has been imported in
   * non benchmarking mode.
   *
   * @param signatureView The signature view to be updated with the imported key.
   */
  public void updateWithImportedKey(SignatureBaseView signatureView) {
    if (signatureView instanceof SignView) {
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
   * Resets the parameters related to pre-loaded keys in the signature processes. This method is
   * used to reset the internal state of the controller, specifically the flags and data related to
   * cross-parameter benchmarking, comparison mode, and provably secure keys. It ensures that the
   * controller's state accurately reflects the absence of pre-loaded keys, particularly after the
   * completion of a benchmarking process or when switching contexts.
   */
  void resetPreLoadedKeyParams() {
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

  public abstract void showStandardMode(Stage primaryStage);

  /**
   * Displays the signature view in benchmarking mode. This method should transition the user
   * interface to a state that supports benchmarking functionalities for signature operations.
   *
   * @param primaryStage The primary stage of the application where the view will be displayed.
   */
  public abstract void showBenchmarkingView(Stage primaryStage);




}
