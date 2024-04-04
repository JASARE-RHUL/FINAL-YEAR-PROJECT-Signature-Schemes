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
import java.util.regex.Pattern;

import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.collections.ListChangeListener;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.stage.Stage;

import uk.msci.project.rsa.MainController;
import uk.msci.project.rsa.BenchmarkingUtility;
import uk.msci.project.rsa.AbstractSignatureBaseController;
import uk.msci.project.rsa.AbstractSignatureModelBenchmarking;
import uk.msci.project.rsa.SignatureModelComparisonBenchmarking;
import uk.msci.project.rsa.SignatureBaseView;
import uk.msci.project.rsa.DigestType;
import uk.msci.project.rsa.SignView;
import uk.msci.project.rsa.PrivateKey;
import uk.msci.project.rsa.PublicKey;
import uk.msci.project.rsa.HashFunctionSelection;


/**
 * This abstract class  provides a skeleton for specific benchmarking
 * controllers to build upon,
 * ensuring a consistent approach across different aspects of signature
 * benchmarking while allowing
 * flexibility for specialised implementations. It provides the core
 * framework for handling
 * benchmarking tasks, facilitating operations like importing batches of
 * messages or signatures,
 * setting up benchmarking observers, and managing custom cross-parameter
 * benchmarking setups.
 */
public abstract class AbstractSignatureBaseControllerBenchmarking extends
  AbstractSignatureBaseController {


  /**
   * Represents the file containing a batch of messages for signature
   * processing.
   */
  File messageBatchFile;

  /**
   * Represents the file containing a batch of signatures for signature
   * verification.
   */
  File signatureBatchFile;


  /**
   * Flag indicating whether the import of a key batch was cancelled. This is
   * used to track the
   * state of key batch importation processes and to handle user actions
   * accordingly.
   */
  boolean isKeyBatchImportCancelled;

  /**
   * An instance of the BenchmarkingUtility class used to manage benchmarking
   * tasks. This utility
   * facilitates the execution and monitoring of tasks related to the
   * benchmarking of signature
   * creation processes. It provides methods to initiate benchmarking tasks,
   * update progress, and
   * handle task completion.
   */
  BenchmarkingUtility benchmarkingUtility;

  /**
   * Flag indicating if the current operation is being conducted in
   * comparison mode. This typically
   * involves comparing standard parameter configurations with provably
   * secure ones.
   */
  boolean isKeyForComparisonMode;


  /**
   * Flag indicating whether the controller is operating in custom
   * cross-parameter benchmarking
   * mode. When set to true, the controller uses the custom configurations
   * specified in
   * keyConfigToHashFunctionsMap.
   */
  boolean isCustomCrossParameterBenchmarkingMode;


  /**
   * A list of strings representing key configuration settings. Each string
   * in the list details a
   * specific configuration used in the key generation process.
   */
  List<String> keyConfigurationStrings;

  /**
   * Maps each key configuration group to a list of hash function selections
   * for custom comparison
   * mode. The key is an integer representing the group index, and the value
   * is a list of pairs.
   * Each pair contains a DigestType representing the hash function and a
   * Boolean indicating if the
   * hash function is provably secure.
   */
  Map<Integer, List<HashFunctionSelection>> keyConfigToHashFunctionsMap =
    new HashMap<>();

  /**
   * Specifies the number of keys per group in a custom cross-parameter
   * benchmarking session. This
   * value determines how many keys are processed together with the same set
   * of hash functions.
   */
  int keysPerGroup = 2;

  /**
   * Indicates whether cross-parameter benchmarking is enabled in the
   * application. This flag is set
   * to true when the application is operating in a mode that allows
   * comparison of signature
   * processes using different key parameter configurations.
   */
  boolean isCrossParameterBenchmarkingEnabled;


  /**
   * Constructs a SignatureBaseController with a reference to the
   * MainController to be used in the
   * event of the user initiating a switch back to main menu.
   *
   * @param mainController The main controller that this controller is part of.
   */
  public AbstractSignatureBaseControllerBenchmarking(MainController mainController) {
    super(mainController);
  }


  /**
   * Sets up observers specific to the benchmarking mode. This method
   * initialises observers for
   * importing text and key batches, cancelling key batch imports, and
   * initiating the benchmarking
   * process. These observers facilitate the interactions required for
   * comprehensive benchmarking
   * activities in signature operations.
   *
   * @param primaryStage   The primary stage of the application where the
   *                       view will be displayed.
   * @param signatureView  The signature view associated with the controller.
   * @param signatureModel The signature model used in benchmarking mode.
   */
  void setupBenchmarkingObservers(Stage primaryStage,
                                  SignatureBaseView signatureView,
                                  AbstractSignatureModelBenchmarking signatureModel) {
    signatureView.addImportTextBatchBtnObserver(
      new ImportObserver(primaryStage, signatureView, signatureModel,
        this::handleMessageBatch,
        "*.txt"));
    signatureView.addImportKeyBatchButtonObserver(
      new ImportObserver(primaryStage, signatureView, signatureModel,
        this::handleKeyBatch, "*.rsa"));
    signatureView.addCancelImportKeyButtonObserver(
      new CancelImportKeyBatchButtonObserver(signatureView, signatureModel));
    signatureView.addCrossParameterToggleObserver(
      new CrossBenchmarkingModeChangeObserver(signatureView,
        AbstractSignatureBaseControllerBenchmarking.this));
  }

  /**
   * Initialises observers for a signature view operating in benchmarking
   * mode. This method includes
   * setup for common observers as well as those specific to benchmarking
   * functionalities, such as
   * batch imports and benchmark initiation.
   *
   * @param primaryStage   The primary stage of the application where the
   *                       view is displayed.
   * @param signatureView  The signature view for which observers are being
   *                       set up.
   * @param signatureModel The signature model used in benchmarking mode.
   */
  void setupObserversBenchmarkingMode(Stage primaryStage,
                                      SignatureBaseView signatureView,
                                      AbstractSignatureModelBenchmarking signatureModel) {
    setupCommonToAllObservers(primaryStage, signatureView, signatureModel);
    setupBenchmarkingObservers(primaryStage, signatureView, signatureModel);
    setupNonCrossBenchmarkingObservers(signatureView, signatureModel);
  }


  /**
   * Handles a batch of messages for signature processing in benchmarking
   * mode. This method is
   * invoked when a file containing multiple messages is imported, catering
   * to either signature
   * creation or verification processes. It processes each message in the
   * batch according to the
   * specific requirements of the benchmarking operation.
   *
   * @param file                       The file containing a batch of messages.
   * @param signatureView              The view associated with this controller.
   * @param signatureModelBenchmarking The benchmarking model for processing
   *                                   the message batch.
   */
  abstract void handleMessageBatch(File file, SignatureBaseView signatureView,
                                   AbstractSignatureModelBenchmarking signatureModelBenchmarking);


  /**
   * Displays the signature view in cross-parameter benchmarking mode. This
   * method should transition
   * the user interface to a state that supports benchmarking of signature
   * operations across
   * different key parameters. ary stage of the application where the view
   * will be displayed.
   */
  abstract void showCrossBenchmarkingView(Stage primaryStage);


  /**
   * The TriConsumer interface represents an operation that accepts three
   * input arguments and
   * returns no result. This is a functional interface whose functional
   * method is accept(Object,
   * Object, Object).
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
   * Observer for canceling the import of a key batch. Handles the event when
   * the user decides to
   * cancel the import of a batch of keys.
   */
  class CancelImportKeyBatchButtonObserver implements EventHandler<ActionEvent> {

    private SignatureBaseView signatureView;
    private AbstractSignatureModelBenchmarking signatureModelBenchmarking;

    public CancelImportKeyBatchButtonObserver(SignatureBaseView signatureView,
                                              AbstractSignatureModelBenchmarking signatureModelBenchmarking) {
      this.signatureView = signatureView;
      this.signatureModelBenchmarking = signatureModelBenchmarking;
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
      signatureModelBenchmarking.clearKeyBatch();
      signatureModelBenchmarking.clearKeyBatch();
      signatureView.setCancelImportKeyButtonVisibility(false);
      signatureView.setImportKeyBatchButtonVisibility(true);

    }
  }

  /**
   * Observer responsible for handling the import of a file. It utilises a
   * file chooser to select a
   * file with a specified extension and then processes it using a provided
   * Consumer.
   */

  class ImportObserver implements EventHandler<ActionEvent> {

    private final Stage stage;
    private final SignatureBaseView signatureView;
    private final AbstractSignatureModelBenchmarking signatureModel;
    private final TriConsumer<File, SignatureBaseView,
      AbstractSignatureModelBenchmarking> fileConsumer;
    private final String fileExtension;

    /**
     * Constructs an observer for importing a file. It uses a file chooser to
     * select a file and then
     * processes it using a provided BiConsumer.
     *
     * @param stage          The primary stage of the application to show the
     *                       file chooser.
     * @param signatureModel The signature model associated with the view.
     * @param signatureView  The signature view to be updated with the
     *                       imported asset.
     * @param fileConsumer   The BiConsumer that processes the selected file
     *                       and updates the view.
     * @param fileExtension  The file extension to filter files in the file
     *                       chooser.
     */
    public ImportObserver(Stage stage, SignatureBaseView signatureView,
                          AbstractSignatureModelBenchmarking signatureModel,
                          TriConsumer<File, SignatureBaseView,
                            AbstractSignatureModelBenchmarking> fileConsumer,
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
   * Handles the file selected by the user containing a batch of keys.
   * Validates the format of the
   * keys and updates the model and view accordingly. It ensures that the key
   * file contains a valid
   * sequence of keys, each separated by a newline, and in a comma-delimited
   * format.
   *
   * @param file           The file containing a batch of keys.
   * @param signatureView  The signature view that will be updated based on
   *                       the imported key batch.
   * @param signatureModel The signature model to be updated with the
   *                       imported key batch.
   * @return true if the keys are valid and imported successfully, false
   * otherwise.
   */
  public boolean handleKeyBatch(File file, SignatureBaseView signatureView,
                                AbstractSignatureModelBenchmarking signatureModel) {

    try (BufferedReader keyReader = new BufferedReader(new FileReader(file))) {
      String keyContent;
      while ((keyContent = keyReader.readLine()) != null) {
        if (!(Pattern.compile("^\\s*\\d+\\s*(,\\s*\\d+\\s*)*$").matcher(keyContent)
          .matches())) {
          uk.msci.project.rsa.DisplayUtility.showErrorAlert(
            "Invalid key batch. Please make sure the file contains a " +
              "contiguous sequence of new line separated and valid keys.");
          return false;
        } else {
          resetPreLoadedKeyParams();
          if (signatureView instanceof SignView) {
            signatureModel.addKeyToBatch(new PrivateKey(keyContent));
          } else {
            signatureModel.addKeyToBatch(new PublicKey(keyContent));
          }
          signatureView.setKey(file.getName());
          signatureView.setCheckmarkImage();
          signatureView.setCheckmarkImageVisibility(true);
          signatureView.setKeyVisibility(true);
        }
      }

    } catch (Exception e) {
      uk.msci.project.rsa.DisplayUtility.showErrorAlert(
        "Invalid key batch. Please make sure the file contains new line " +
          "separated contiguous sequence of valid keys.");
      return false;
    }

    signatureView.setImportKeyBatchButtonVisibility(false);
    signatureView.setCancelImportKeyButtonVisibility(true);
    return true;
  }

  /**
   * Checks a file for non-empty lines and counts the number of valid lines.
   * This method is used to
   * validate message or signature batch files to ensure they meet the
   * expected format.
   *
   * @param file     The file to be checked.
   * @param artefact A string describing the artefact being checked (e.g.,
   *                 "message", "signature").
   * @return The number of non-empty lines if the file is valid, otherwise 0.
   */
  public int checkFileForNonEmptyLines(File file, String artefact) {
    boolean encounteredNonEmptyLine = false; // Flag to track if any
    // non-empty line has been encountered
    boolean isValidFile = true; // Flag to denote if file is valid
    int numMessages = 0; // Counter for the number of non-empty lines

    try (BufferedReader messageReader =
           new BufferedReader(new FileReader(file))) {
      String messageString;
      // Iterate through each line in the file
      while ((messageString = messageReader.readLine()) != null) {
        if (!messageString.isEmpty()) {
          // Non-empty line encountered
          encounteredNonEmptyLine = true;
          numMessages++; // Increment the non-empty line count
        } else if (encounteredNonEmptyLine) {
          // Empty line encountered after non-empty line, indicating invalid
          // file
          uk.msci.project.rsa.DisplayUtility.showErrorAlert(
            "Invalid " + artefact + " batch. Please make sure the file " +
              "contains no empty lines.");
          isValidFile = false;
          break;
        }
      }
    } catch (IOException e) {
      // Handle IOException during file reading
      uk.msci.project.rsa.DisplayUtility.showErrorAlert("Error reading file: "
        + e.getMessage());
      isValidFile = false;
    }

    if (!isValidFile) {
      // Show error alert if file is not valid
      uk.msci.project.rsa.DisplayUtility.showErrorAlert(
        "Invalid " + artefact + " batch. Please make sure the file contains a" +
          " contiguous sequence" +
          " of new line separated messages that matches the number entered in" +
          " the above field.");
    }

    return isValidFile ? numMessages : 0; // Return number of valid lines if
    // file is valid, else 0
  }


  /**
   * Updates the signature model and view with an imported batch of keys.
   * This method is used to
   * process the imported key batch, adding each key to the signature model,
   * and reflecting the
   * import status in the signature view. It is particularly useful in
   * scenarios involving batch
   * processing of multiple keys.
   *
   * @param signatureView              The signature view to be updated with
   *                                   the imported key
   *                                   batch.
   * @param signatureModelBenchmarking The benchmarking model for which the
   *                                   keys are imported.
   */
  public void updateWithImportedKeyBatch(SignatureBaseView signatureView,
                                         AbstractSignatureModelBenchmarking signatureModelBenchmarking,
                                         String keyFieldString) {
    try (BufferedReader reader =
           new BufferedReader(new StringReader(this.importedKeyBatch))) {
      String keyContent;
      // Loop through each line in the imported key batch
      while ((keyContent = reader.readLine()) != null) {
        if (signatureView instanceof SignView) {
          signatureModelBenchmarking.addKeyToBatch(new PrivateKey(keyContent));
        } else {
          signatureModelBenchmarking.addKeyToBatch(new PublicKey(keyContent));
        }
      }
    } catch (IOException e) {
      // Print stack trace for IOException
      e.printStackTrace();
    }
    // Update the view with the key field string
    signatureView.setKey(keyFieldString);

    // Set checkmark image and make it visible along with the key field in
    // the view
    signatureView.setCheckmarkImage();
    signatureView.setCheckmarkImageVisibility(true);
    signatureView.setKeyVisibility(true);
  }


  /**
   * Observer for changes in the Cross Benchmarking Mode. This observer
   * handles the toggle event
   * between enabling and disabling cross benchmarking mode. It launches an
   * FXML file with
   * specialised cross-parameter benchmarking options when the toggle is
   * switched on and does not
   * allow a user to switch the toggle on, unless a key in the format
   * expected for the mode and been
   * preloaded implicitly through the prior key generation process where the
   * option was selected.
   */
  class CrossBenchmarkingModeChangeObserver implements ChangeListener<Boolean> {

    private SignatureBaseView signatureView;
    private final AbstractSignatureBaseControllerBenchmarking signatureBaseControllerBenchmarking;


    public CrossBenchmarkingModeChangeObserver(SignatureBaseView signatureView,
                                               AbstractSignatureBaseControllerBenchmarking signatureBaseControllerBenchmarking) {
      this.signatureView = signatureView;
      this.signatureBaseControllerBenchmarking =
        signatureBaseControllerBenchmarking;
    }

    @Override
    public void changed(ObservableValue<? extends Boolean> observableValue,
                        Boolean oldValue,
                        Boolean newValue) {
      if (Boolean.TRUE.equals(newValue) && Boolean.FALSE.equals(oldValue)) {
        try {
          signatureBaseControllerBenchmarking.showCrossBenchmarkingView(
            mainController.getPrimaryStage());
        } catch (IllegalStateException e) {
          signatureView.setSelectedCrossParameterToggleObserver(false);
          uk.msci.project.rsa.DisplayUtility.showErrorAlert(
            "Cross parameter benchmarking cannot be enabled without an " +
              "initial cross parameter generation of keys.");
        }
      } else if (Boolean.FALSE.equals(newValue) && Boolean.TRUE.equals(oldValue)) {
        if (isKeyBatchImportCancelled || (isCrossParameterBenchmarkingEnabled)) {
          isKeyBatchImportCancelled = false;
          signatureBaseControllerBenchmarking.showBenchmarkingView(
            mainController.getPrimaryStage());
        }
      }
    }
  }


  /**
   * Imports a key from the key generation process. This method sets the
   * state of the controller to
   * reflect that a key has been imported for comparison mode or provably
   * secure mode, based on the
   * provided parameters. It updates the internal state with the imported key
   * batch.
   *
   * @param keyBatch               The batch of keys generated and to be
   *                               imported.
   * @param isKeyForComparisonMode Indicates if the key is for comparison mode.
   */
  public void importKeyFromKeyGeneration(String keyBatch,
                                         boolean isKeyForComparisonMode) {
    this.isKeyProvablySecure = !isKeyForComparisonMode;
    this.isCrossParameterBenchmarkingEnabled = isKeyForComparisonMode;
    this.isKeyForComparisonMode = isKeyForComparisonMode;
    importedKeyBatch = keyBatch;
  }


  /**
   * Sets the hash size in the signature model based on the hash output size
   * specified by the user.
   * This method is invoked when there is a need to update the model with the
   * hash size, especially
   * when using variable length hash functions in custom mode. It validates
   * the hash output size
   * entered by the user to ensure it is a non-negative integer and falls
   * within the acceptable
   * range. If the validation fails or if the hash output size field is not
   * visible (not required
   * for the selected hash function), the method will not update the model
   * and will return false.
   * This method is crucial for maintaining the consistency of the signature
   * model state with the
   * user's input on the view.
   * <p>
   *
   * @param signatureView The signature view that provides context for hash
   *                      size setting.
   * @return Boolean value indicating if validation failed.
   */
  boolean setHashSizeInModelBenchmarking(SignatureBaseView signatureView,
                                         AbstractSignatureModelBenchmarking signatureModelBenchmarking) {
    if (signatureView.getHashOutputSizeAreaVisibility()) {
      if (!handleHashOutputSizeBenchmarking(signatureModelBenchmarking)) {
        return false;
      }
    }
    return true;
  }


  /**
   * Handles the input for custom hash output size configuration. This method
   * validates the user
   * input to ensure it matches a fraction format (e.g., "1/2") and verifies
   * that the numerator is
   * less than the denominator. The fraction is used to determine the
   * proportion of the modulus size
   * for the hash output in signature operations in benchmarking mode.
   * <p>
   * The method updates the model with the calculated fraction if the input
   * is valid. If the input
   * is invalid, an error alert is displayed to the user, requesting them to
   * provide a valid
   * fraction.
   *
   * @return {@code true} if the hash output size input is valid and
   * successfully processed, {@code
   * false} otherwise.
   */
  public boolean handleHashOutputSizeBenchmarking(
    AbstractSignatureModelBenchmarking signatureModelBenchmarking) {
    boolean invalidField = false;
    int[] fractionsArray = validateFraction(hashOutputSize);

    if (fractionsArray == null) {
      invalidField = true;
      uk.msci.project.rsa.DisplayUtility.showErrorAlert(
        "Please enter a valid fraction representing the desired proportion of" +
          " the modulus size for the hash output. Try again.");
    } else {
      signatureModelBenchmarking.setCustomHashSizeFraction(fractionsArray);
    }

    return !invalidField;
  }

  /**
   * Sets the list of key configuration strings corresponding to settings
   * used to generate the
   * various keys for each key size selected by the user in the key
   * generation process.
   *
   * @param keyConfigurationStrings A list of key configuration strings.
   */
  public void setKeyConfigurationStrings(List<String> keyConfigurationStrings) {
    this.keyConfigurationStrings = keyConfigurationStrings;
  }

  /**
   * Sets the mapping of key configurations to hash functions for custom
   * comparison benchmarking
   * mode. This method updates the controller's state with the specified
   * mapping and the number of
   * keys per group, enabling detailed comparative analysis of signature
   * processes under various
   * cryptographic conditions.
   *
   * @param keyConfigToHashFunctionsMap The mapping of key configurations to
   *                                    their respective hash
   *                                    functions.
   * @param keysPerGroup                The number of keys in each group for
   *                                    batch processing.
   */
  public void setKeyConfigToHashFunctionsMap(
    Map<Integer, List<HashFunctionSelection>> keyConfigToHashFunctionsMap,
    int keysPerGroup) {
    this.keyConfigToHashFunctionsMap = keyConfigToHashFunctionsMap;
    this.keysPerGroup = keysPerGroup;
  }


  /**
   * Preloads a batch of provably secure keys into the signature view for
   * batch operations in
   * benchmarking mode. This setup is essential for operations that require a
   * sequence of provably
   * secure keys, typically used in scenarios where multiple signatures are
   * created or verified
   * under controlled conditions.
   *
   * @param signatureView              The signature view to be updated with
   *                                   the preloaded key
   *                                   batch.
   * @param signatureModelBenchmarking The benchmarking model used in
   *                                   conjunction with the preloaded
   *                                   keys.
   */
  void preloadProvablySecureKeyBatch(SignatureBaseView signatureView,
                                     AbstractSignatureModelBenchmarking signatureModelBenchmarking) {
    if (this.importedKeyBatch != null
      && !isCrossParameterBenchmarkingEnabled) {
      updateWithImportedKeyBatch(signatureView, signatureModelBenchmarking,
        "A provably-secure key batch was loaded");
      signatureView.setImportKeyBatchButtonVisibility(false);
      signatureView.setCancelImportKeyButtonVisibility(true);
      signatureView.setProvableParamsHboxVisibility(true);
      signatureView.setProvablySecureParametersRadioSelected(true);
      signatureView.setCustomParametersRadioVisibility(false);
      signatureView.setStandardParametersRadioVisibility(false);
    }
  }

  /**
   * Preloads a batch of keys for cross-parameter benchmarking into the
   * signature view. This method
   * sets up the view with a batch of keys that are compatible for cross
   * parameter benchmarking
   * mode.
   *
   * @param signatureView                        The signature view to be
   *                                             updated with the
   *                                             cross-parameter key batch.
   * @param signatureModelComparisonBenchmarking
   */
  void preloadCrossParameterKeyBatch(SignatureBaseView signatureView,
                                     SignatureModelComparisonBenchmarking signatureModelComparisonBenchmarking) {
    updateWithImportedKeyBatch(signatureView,
      signatureModelComparisonBenchmarking,
      "Keys were loaded for cross-parameter comparison");
    signatureModelComparisonBenchmarking.setNumKeysPerKeySizeComparisonMode(
      keyConfigurationStrings.size());
    signatureModelComparisonBenchmarking.setKeyConfigurationStrings(keyConfigurationStrings);
    if (isCrossParameterBenchmarkingEnabled && this.importedKeyBatch != null) {
      signatureView.setImportKeyBatchButtonVisibility(false);
      signatureView.setCancelImportKeyButtonVisibility(true);
    }
  }

  /**
   * Preloads hash function configurations for custom cross-parameter
   * benchmarking mode. This method
   * is invoked to set up the signature model with the predefined hash
   * function mappings and the
   * number of keys per group for batch processing.
   *
   * @param signatureView The signature view to be updated with hash function
   *                      configurations.
   */
  void preloadCustomCrossParameterHashFunctions(SignatureBaseView signatureView,
                                                SignatureModelComparisonBenchmarking signatureModelComparisonBenchmarking) {
    if (keyConfigToHashFunctionsMap != null && isCustomCrossParameterBenchmarkingMode) {
      signatureModelComparisonBenchmarking.setKeyConfigToHashFunctionsMap(
        keyConfigToHashFunctionsMap);
      signatureModelComparisonBenchmarking.setKeysPerGroup(keysPerGroup);
      signatureView.setProvableHashChoiceComparisonModeHboxVisibility(false);
      signatureView.setStandardHashChoiceComparisonModeHboxVisibility(false);
    } else {
      signatureModelComparisonBenchmarking.setKeysPerGroup(2);
    }
  }


  /**
   * Sets up observers for a signature view in cross-parameter benchmarking
   * mode. This method
   * includes observers specific to handling standard and provably secure
   * hash function changes,
   * along with other functionalities unique to cross-parameter benchmarking.
   *
   * @param primaryStage   The primary stage of the application where the
   *                       view is displayed.
   * @param signatureView  The signature view for which observers are being
   *                       set up.
   * @param signatureModel The signature model used in cross-parameter
   *                       benchmarking mode.
   */
  void setupObserversCrossBenchmarking(Stage primaryStage,
                                       SignatureBaseView signatureView,
                                       AbstractSignatureModelBenchmarking signatureModel) {
    setupCommonToAllObservers(primaryStage, signatureView, signatureModel);
    setupBenchmarkingObservers(primaryStage, signatureView, signatureModel);
    signatureView.addStandardHashFunctionChangeObserver(new StandardHashFunctionChangeObserver(
      (SignatureModelComparisonBenchmarking) signatureModel));
    signatureView.addProvableHashFunctionChangeObserver(new ProvableHashFunctionChangeObserver(
      (SignatureModelComparisonBenchmarking) signatureModel));
  }


  /**
   * Observer for changes in the selection of provably secure hash functions
   * in cross-parameter
   * benchmarking mode. Handles the addition or removal of provably secure
   * hash function choices in
   * the UI and updates the signature model accordingly.
   */
  class ProvableHashFunctionChangeObserver implements ListChangeListener<String> {

    private SignatureModelComparisonBenchmarking signatureModelComparisonBenchmarking;


    public ProvableHashFunctionChangeObserver(
      SignatureModelComparisonBenchmarking signatureModelComparisonBenchmarking) {
      this.signatureModelComparisonBenchmarking =
        signatureModelComparisonBenchmarking;
    }

    @Override
    public void onChanged(Change<? extends String> c) {
      while (c.next()) {
        if (c.wasAdded()) {
          for (String addedType : c.getAddedSubList()) {
            signatureModelComparisonBenchmarking.getCurrentProvableHashTypeList_ComparisonMode()
              .add(new HashFunctionSelection(DigestType.getDigestTypeFromCustomString(addedType),
                true, null));
          }
        } else if (c.wasRemoved()) {
          for (String removedType : c.getRemoved()) {
            signatureModelComparisonBenchmarking.getCurrentProvableHashTypeList_ComparisonMode()
              .remove((new HashFunctionSelection(
                DigestType.getDigestTypeFromCustomString(removedType), true,
                null)));
          }
        }

      }
    }

  }

  /**
   * Observer for changes in the selection of standard hash function. This
   * observer responds to
   * change in hash function selection when in cross parameter benchmarking
   * mode and updates the
   * signature model accordingly. It sets...
   */
  class StandardHashFunctionChangeObserver implements ListChangeListener<String> {

    private SignatureModelComparisonBenchmarking signatureModelComparisonBenchmarking;


    public StandardHashFunctionChangeObserver(
      SignatureModelComparisonBenchmarking signatureModelComparisonBenchmarking) {
      this.signatureModelComparisonBenchmarking =
        signatureModelComparisonBenchmarking;
    }

    @Override
    public void onChanged(Change<? extends String> c) {
      while (c.next()) {
        if (c.wasAdded()) {
          for (String addedType : c.getAddedSubList()) {
            signatureModelComparisonBenchmarking.getCurrentFixedHashTypeList_ComparisonMode()
              .add((new HashFunctionSelection(DigestType.getDigestTypeFromCustomString(addedType),
                false, null)));
          }
        } else if (c.wasRemoved()) {
          for (String removedType : c.getRemoved()) {
            signatureModelComparisonBenchmarking.getCurrentFixedHashTypeList_ComparisonMode()
              .remove((new HashFunctionSelection(
                DigestType.getDigestTypeFromCustomString(removedType), false,
                null)));
          }
        }

      }
    }
  }

  /**
   * Resets the parameters related to pre-loaded keys in the signature
   * processes. This method is
   * used to reset the internal state of the controller, specifically the
   * flags and data related to
   * cross-parameter benchmarking, comparison mode, and provably secure keys.
   * It ensures that the
   * controller's state accurately reflects the absence of pre-loaded keys,
   * particularly after the
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
  }


  /**
   * Sets the flag to indicate whether the controller is operating in custom
   * cross-parameter
   * benchmarking mode. When this mode is enabled, the controller uses the
   * custom hash function
   * mappings and key configurations specified for detailed comparison.
   *
   * @param isCustomCrossParameterBenchmarkingMode Flag indicating the custom
   *                                               cross-parameter
   *                                               benchmarking mode.
   */
  public void setIsCustomCrossParameterBenchmarkingMode(
    boolean isCustomCrossParameterBenchmarkingMode) {
    this.isCustomCrossParameterBenchmarkingMode =
      isCustomCrossParameterBenchmarkingMode;
  }


}
