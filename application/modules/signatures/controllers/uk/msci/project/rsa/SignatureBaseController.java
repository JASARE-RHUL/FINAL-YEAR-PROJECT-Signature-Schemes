package uk.msci.project.rsa;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BiConsumer;
import java.util.regex.Pattern;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.scene.control.RadioButton;
import javafx.scene.control.Toggle;
import javafx.stage.Stage;
import uk.msci.project.rsa.SignatureCreationController.CancelImportTextButtonObserver;


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
   * Constructs a SignatureBaseController with a reference to the MainController to be used in the
   * event of the user initiating a switch back to main menu.
   *
   * @param mainController The main controller that this controller is part of.
   */
  public SignatureBaseController(MainController mainController) {
    this.mainController = mainController;
  }

  /**
   * Handles the importing of a key file. Validates the key and updates the model and view
   * accordingly. It expects the key file to contain a specific format and updates the view based on
   * the result of the key validation.
   *
   * @param file    The key file selected by the user.
   * @param viewOps The {@code ViewUpdate} operations that will update the view.
   */
  public void handleKey(File file, ViewUpdate viewOps) {
    String content = "";
    try {
      content = FileHandle.importFromFile(file);
    } catch (Exception e) {
      uk.msci.project.rsa.DisplayUtility.showErrorAlert("Error importing file, please try again.");
    }
    if (!(Pattern.compile("^\\d+,\\d+$").matcher(content).matches())) {
      uk.msci.project.rsa.DisplayUtility.showErrorAlert(
          "Error: Invalid key. Key could not be imported.");
    } else {
      if (viewOps instanceof SignViewUpdateOperations) {
        signatureModel.setKey(new PrivateKey(content));
      } else {
        signatureModel.setKey(new PublicKey(content));
      }
      viewOps.setKeyName(file.getName());
      viewOps.updateCheckmarkImage();
      viewOps.setCheckmarkVisibility(true);
      viewOps.setKeyVisibility(true);

    }
  }


  /**
   * Observer responsible for handling the import of a file. It utilises a file chooser to select a
   * file with a specified extension and then processes it using a provided Consumer.
   */

  class ImportObserver implements EventHandler<ActionEvent> {

    private final Stage stage;
    private final BiConsumer<File, ViewUpdate> fileConsumer;
    private final ViewUpdate viewOps;
    private final String fileExtension;

    /**
     * Constructs an observer for importing a file. It uses a file chooser to select a file and then
     * processes it using a provided BiConsumer.
     *
     * @param stage         The primary stage of the application to show the file chooser.
     * @param viewOps       The {@code ViewUpdate} operations that will update the view.
     * @param fileConsumer  The BiConsumer that processes the selected file and updates the view.
     * @param fileExtension The file extension to filter files in the file chooser.
     */
    public ImportObserver(Stage stage, ViewUpdate viewOps,
        BiConsumer<File, ViewUpdate> fileConsumer, String fileExtension) {
      this.stage = stage;
      this.viewOps = viewOps;
      this.fileConsumer = fileConsumer;
      this.fileExtension = fileExtension;
    }

    @Override
    public void handle(ActionEvent event) {
      uk.msci.project.rsa.DisplayUtility.handleFileImport(stage, fileExtension,
          file -> fileConsumer.accept(file, viewOps));
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
   * @param file    The file selected by the user containing the message to sign.
   * @param viewOps The {@code ViewUpdate} operations that will update the view.
   */
  public void handleMessageFile(File file, ViewUpdate viewOps) {
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
      viewOps.setTextInput("");
      viewOps.setTextFileNameLabel(file.getName());
      viewOps.setTextInputVisibility(false);
      viewOps.setTextFileCheckmarkImage();
      viewOps.setTextInputHBoxVisibility(true);
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
   * The observer for changes in parameter choice (standard vs. provably secure). This class reacts
   * to change in the selected parameter option and updates the model accordingly.
   */
  class ParameterChoiceChangeObserver implements ChangeListener<Toggle> {

    @Override
    public void changed(ObservableValue<? extends Toggle> observable, Toggle oldValue,
        Toggle newValue) {
      if (newValue != null) {
        RadioButton selectedRadioButton = (RadioButton) newValue;
        String radioButtonText = selectedRadioButton.getText();
        switch (radioButtonText) {
          case "Provably Secure Parameters":
            signatureModel.setProvablySecure(true);
            break;
          case "Standard Parameters":
          default:
            signatureModel.setProvablySecure(false);
            break;

        }
      }
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

    private SignatureViewInterface viewInterface;

    public BackToMainMenuObserver(SignatureViewInterface viewInterface) {
      this.viewInterface = viewInterface;
    }

    @Override
    public void handle(ActionEvent event) {
      mainController.showMainMenuView();
      viewInterface = null;
      signatureModel = null;
    }

  }

  /**
   * Observer for canceling the import of a key batch. Handles the event when the user decides to
   * cancel the import of a batch of keys.
   */
  class CancelImportKeyButtonObserver implements EventHandler<ActionEvent> {

    private ViewUpdate viewOps;

    public CancelImportKeyButtonObserver(ViewUpdate viewOps) {
      this.viewOps = viewOps;
    }

    @Override
    public void handle(ActionEvent event) {
      viewOps.setCheckmarkVisibility(false);
      viewOps.setKeyName("Please Import a private key batch");
      signatureModel.clearPrivateKeyBatch();
      signatureModel.clearPublicKeyBatch();
      viewOps.setCancelImportKeyButtonVisibility(false);
      viewOps.setImportKeyBatchButtonVisibility(true);

    }
  }

  /**
   * Handles the file selected by the user for a batch of keys. It validates the keys and updates
   * the model and view accordingly. It expects the key file to contain a line separated text of
   * comma delimited positive integers and updates the view based on the result of the key
   * validation.
   *
   * @param file    The file selected by the user containing a batch of keys.
   * @param viewOps The {@code ViewUpdate} operations that will update the view.
   */
  public boolean handleKeyBatch(File file, ViewUpdate viewOps) {
    try (BufferedReader keyReader = new BufferedReader(new FileReader(file))) {
      String keyContent;
      while ((keyContent = keyReader.readLine()) != null) {
        if (!(Pattern.compile("^\\s*\\d+\\s*(,\\s*\\d+\\s*)*$").matcher(keyContent)
            .matches())) {
          uk.msci.project.rsa.DisplayUtility.showErrorAlert(
              "Invalid key batch. Please make sure the file contains a contiguous sequence of new line separated and valid keys.");
          return false;
        } else {
          if (this instanceof SignatureCreationController) {
            signatureModel.addPrivKeyToBatch(keyContent);
          } else {
            signatureModel.addPublicKeyToBatch(keyContent);
          }
          viewOps.setKeyName(file.getName());
          viewOps.updateCheckmarkImage();
          viewOps.setCheckmarkVisibility(true);
          viewOps.setKeyVisibility(true);
        }
      }

    } catch (Exception e) {
      uk.msci.project.rsa.DisplayUtility.showErrorAlert(
          "Invalid key batch. Please make sure the file contains new line separated contiguous sequence of valid keys.");
      return false;
    }
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


}
