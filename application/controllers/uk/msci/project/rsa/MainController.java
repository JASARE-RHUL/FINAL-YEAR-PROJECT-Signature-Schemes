package uk.msci.project.rsa;


import java.io.IOException;
import java.util.List;
import java.util.Map;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.layout.Pane;
import javafx.stage.Stage;

/**
 * This class serves as the central controller for the application, managing navigation between
 * different views and coordinating actions across the entire program.
 */
public class MainController {

  /**
   * The primary stage for the application. This is the main window or frame of the JavaFX
   * application where different views are displayed.
   */
  private Stage primaryStage;
  /**
   * The main scene for the application. This is the container for all content in a scene graph.
   */
  private Scene scene;
  /**
   * The main menu view of the application. This view serves as the starting point of the
   * application, allowing navigation to core functionality.
   */
  private MainMenuView mainMenuView;

  /**
   * Mediator for key generation functionalities. It encapsulates and manages the interaction
   * between the main controller and the key generation controllers, both in standard and
   * benchmarking modes.
   */
  private KeyGenerationMediator keyGenerationMediator = new KeyGenerationMediator(this);

  /**
   * Mediator for signature creation functionalities. It encapsulates and manages the interaction
   * between the main controller and the signature creation controllers, both in standard and
   * benchmarking modes.
   */
  private SignatureCreationMediator signatureCreationMediator = new SignatureCreationMediator(this);

  /**
   * Mediator for signature verification functionalities. Similar to signatureCreationMediator, this
   * mediator handles the interaction between the main controller and the signature verification
   * controllers for both standard and benchmarking modes.
   */
  private SignatureVerificationMediator signatureVerificationMediator = new SignatureVerificationMediator(
      this);


  /**
   * Constructs a MainController with the primary stage of the application. This constructor
   * initialises the controller with the main application stage and displays the main menu view.
   *
   * @param primaryStage The primary stage of the application.
   */
  public MainController(Stage primaryStage) {
    this.primaryStage = primaryStage;
    scene = new Scene(new Pane());

    // Initially show the MainMenuView
    showMainMenuView();
  }

  /**
   * Displays the main menu view on the primary stage. It loads the MainMenuView from the FXML file,
   * initialises its domain object, and sets it on the stage.
   */
  void showMainMenuView() {
    try {

      FXMLLoader loader = new FXMLLoader(getClass().getResource("/MainMenuView.fxml"));
      Parent root = loader.load();
      scene.setRoot(root);
      mainMenuView = loader.getController();
      primaryStage.setScene(scene);
      primaryStage.show();
      mainMenuView.addGenerateKeysObserver(new GenerateKeysButtonObserver());
      mainMenuView.addSignDocumentObserver(new SignDocumentObserver());
      mainMenuView.addVerifySignatureObserver(new verifySignatureObserver());
    } catch (IOException e) {
      e.printStackTrace();
    }
  }


  /**
   * Retrieves the SignatureCreationControllerBenchmarking instance. This controller is responsible
   * for handling the signature creation process in benchmarking mode.
   *
   * @return The SignatureCreationControllerBenchmarking instance.
   */
  public SignatureCreationControllerBenchmarking getSignatureCreationControllerBenchmarking() {
    return (SignatureCreationControllerBenchmarking) signatureCreationMediator.getSignatureControllerBenchmarking();
  }

  /**
   * Retrieves the SignatureCreationControllerBenchmarking instance. This controller is responsible
   * for handling the signature creation process in benchmarking mode.
   *
   * @return The SignatureCreationControllerBenchmarking instance.
   */
  public SignatureCreationControllerStandard getSignatureCreationControllerStandard() {
    return (SignatureCreationControllerStandard) signatureCreationMediator.getSignatureControllerStandard();
  }

  /**
   * Retrieves the SignatureVerificationControllerBenchmarking instance. This controller is
   * responsible for handling the signature verification process in benchmarking mode.
   *
   * @return The SignatureVerificationControllerBenchmarking instance.
   */
  public SignatureVerificationControllerBenchmarking getSignatureVerificationControllerBenchmarking() {
    return (SignatureVerificationControllerBenchmarking) signatureVerificationMediator.getSignatureControllerBenchmarking();
  }

  /**
   * Retrieves the SignatureVerificationControllerStandard instance. This controller is responsible
   * for managing the signature verification process in standard mode.
   *
   * @return The SignatureVerificationControllerStandard instance.
   */
  public SignatureVerificationControllerStandard getSignatureVerificationControllerStandard() {
    return (SignatureVerificationControllerStandard) signatureVerificationMediator.getSignatureControllerStandard();
  }

  /**
   * Observers the "Generate Keys" button click. Instantiates the GenController and displays the key
   * generation view.
   */
  class GenerateKeysButtonObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
      keyGenerationMediator.showBenchmarkingView();
    }
  }

  /**
   * Observes "Sign Document" button click. Instantiates the SignatureCreationController and
   * displays the document signing view. Depending on whether a key has been pre-loaded for standard
   * mode, the non benchmarking signing view may be launched.
   */
  class SignDocumentObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
      if (signatureCreationMediator.getIsSingleKeyProvablySecure()) {
        signatureCreationMediator.showSignatureViewStandard();
      } else if (signatureCreationMediator.getComparisonBenchmarkingImport() != null) {
        signatureCreationMediator.showSignatureViewComparisonBenchmarking();
      } else {
        signatureCreationMediator.showSignatureViewBenchmarking();
      }
    }
  }

  /**
   * Observes "verify signature" button click. Instantiates the SignatureVerificationController and
   * displays the signature verification view. Depending on whether a key has been pre-loaded for
   * standard  mode, the non benchmarking verification view may be launched.
   */
  class verifySignatureObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
      if (signatureVerificationMediator.getIsSingleKeyProvablySecure()) {
        signatureVerificationMediator.showSignatureViewStandard();
      } else if (signatureVerificationMediator.getComparisonBenchmarkingImport() != null) {
        signatureVerificationMediator.showSignatureViewComparisonBenchmarking();
      } else {
        signatureVerificationMediator.showSignatureViewBenchmarking();
      }
    }
  }

  /**
   * Gets the primary stage of the application.
   *
   * @return The primary stage of the application.
   */
  public Stage getPrimaryStage() {
    return primaryStage;
  }

  /**
   * Sets the root of the main scene to the provided parent node. This method is used to change the
   * content displayed in the primary stage of the application.
   *
   * @param parent The root node of the new content to be displayed on the scene.
   */
  public void setScene(Parent parent) {
    scene.setRoot(parent);
    primaryStage.setScene(scene);
  }


  /**
   * Retrieves the main scene of the application. This scene is used as the primary container for
   * all content in the application's user interface.
   *
   * @return The main Scene of the application.
   */
  public Scene getScene() {
    return scene;
  }


  /**
   * Sets the batch of private and public keys for both signature creation and verification
   * processes. This method is crucial for handling the application's functionality in different
   * modes, specifically in comparison and custom comparison benchmarking modes. It delegates the
   * process of setting keys for the signature creation and verification controllers, allowing these
   * controllers to operate with the specified keys.
   * <p>
   * In comparison mode, this method helps in setting up the environment for comparing the standard
   * vs provably secure parameters. In custom comparison mode, it facilitates a more granular and
   * detailed analysis with arbitrary user provided key configurations.
   *
   * @param privateKeyBatch              The batch of private keys used in the signature creation
   *                                     process.
   * @param publicKeyBatch               The batch of public keys used in the signature verification
   *                                     process.
   * @param isKeyForComparisonMode       Indicates if the keys are used in comparison mode, enabling
   *                                     performance comparison.
   * @param isKeyForCustomComparisonMode Indicates if the keys are set for custom comparison mode,
   *                                     enabling detailed analysis with custom configurations.
   */
  public void setProvableKeyBatchForSignatureProcesses(String privateKeyBatch,
      String publicKeyBatch,
      boolean isKeyForComparisonMode, boolean isKeyForCustomComparisonMode) {
    signatureCreationMediator.setProvableKeyBatchForSignatureProcesses(privateKeyBatch,
        isKeyForComparisonMode, isKeyForCustomComparisonMode);
    signatureVerificationMediator.setProvableKeyBatchForSignatureProcesses(
        publicKeyBatch, isKeyForComparisonMode, isKeyForCustomComparisonMode);
  }

  /**
   * Sets the private/public key for signature verification/creation operations. This method is used
   * to provide the signature controller with a provably secure generated (small e ) key pairing to
   * allow for later instantiation of a signature scheme with provably secure parameters. The key
   * pairing can be set in non-benchmarking mode.
   *
   * @param privateKey The private key to be used for signature creation.
   * @param publicKey  The public key to be used for signature verification.
   */
  public void setProvableKeyForSignatureProcesses(String privateKey, String publicKey) {
    signatureCreationMediator.setProvableKeyForSignatureProcesses(privateKey);
    signatureVerificationMediator.setProvableKeyForSignatureProcesses(publicKey);
  }


  /**
   * Sets the list of key configuration strings for comparison mode across the signature controller
   * assembly by providing configuration details of the keys used in the comparison benchmarking
   * mode. The configuration strings represent different key configurations that are used to compare
   * signature processes under different key settings.
   *
   * @param keyConfigurationStringsForComparisonMode A list of string representations of key
   *                                                 configurations.
   */
  public void setKeyConfigurationStringsForComparisonMode(
      List<String> keyConfigurationStringsForComparisonMode) {
    signatureCreationMediator.setKeyConfigurationStringsForComparisonMode(
        keyConfigurationStringsForComparisonMode);
    signatureVerificationMediator.setKeyConfigurationStringsForComparisonMode(
        keyConfigurationStringsForComparisonMode);
  }

  /**
   * Sets the mapping of key configurations to hash functions for the custom comparison mode in
   * signature creation and verification controllers. This method allows for specifying different
   * hash functions for each group of key configurations.
   *
   * @param keyConfigToHashFunctionsMap The map linking each key configuration group to its hash
   *                                    function selections.
   * @param keyPerGroup                 The number of keys per group, determining how many keys are
   *                                    processed together.
   */
  public void setKeyConfigToHashFunctionsMapForCustomComparisonMode(
      Map<Integer, List<HashFunctionSelection>> keyConfigToHashFunctionsMap, int keyPerGroup) {
    signatureCreationMediator.setKeyConfigToHashFunctionsMapForCustomComparisonMode(
        keyConfigToHashFunctionsMap, keyPerGroup);
    signatureVerificationMediator.setKeyConfigToHashFunctionsMapForCustomComparisonMode(
        keyConfigToHashFunctionsMap, keyPerGroup);

  }

  /**
   * Displays the signature creation view in the standard mode with no benchmarking functionality.
   */
  public void showSignatureCreationStandard() {
    signatureCreationMediator.showSignatureViewStandard();
  }

  /**
   * Displays the signature creation view for comparison benchmarking mode. This method updates the
   * UI to present an interface tailored for comparing signature creation performance across
   * different key configurations.
   */
  public void showSignatureCreationComparisonBenchmarking() {
    signatureCreationMediator.showSignatureViewComparisonBenchmarking();
  }

  /**
   * Displays the signature verification view for comparison benchmarking mode. This method updates
   * the UI to present an interface specifically designed for comparing signature verification
   * performance across various key configurations.
   */
  public void showSignatureVerificationComparisonBenchmarking() {
    signatureVerificationMediator.showSignatureViewComparisonBenchmarking();
  }


  /**
   * Displays the signature creation view in benchmarking mode. This method triggers the UI update
   * to show the interface for signature creation with benchmarking functionalities.
   */
  public void showSignatureCreationBenchmarking() {
    signatureCreationMediator.showSignatureViewBenchmarking();
  }

  /**
   * Displays the signature verification view in standard mode. This method updates the UI to
   * present the interface for standard signature verification.
   */
  public void showSignatureVerificationStandard() {
    signatureVerificationMediator.showSignatureViewStandard();
  }

  /**
   * Displays the signature verification view in benchmarking mode. This method updates the UI to
   * present the interface for signature verification with benchmarking functionalities.
   */
  public void showSignatureVerificationBenchmarking() {
    signatureVerificationMediator.showSignatureViewBenchmarking();
  }


  /**
   * Retrieves the imported key batch to be preloaded in comparison benchmarking mode for the
   * signature creation process.
   *
   * @return A string representing the imported key batch
   */
  public String getSignatureCreationComparisonBenchmarkingImport() {
    return signatureCreationMediator.getComparisonBenchmarkingImport();
  }

  /**
   * Retrieves the imported key batch to be preloaded in comparison benchmarking mode for the
   * signature verification process.
   *
   * @return A string representing the imported key batch
   */
  public String getSignatureVerificationComparisonBenchmarkingImport() {
    return signatureVerificationMediator.getComparisonBenchmarkingImport();
  }

  /**
   * Displays the key generation view in benchmarking mode. This method triggers the UI update to
   * show the interface for key generation with benchmarking functionalities.
   */
  public void showGenViewBenchmarking() {
    keyGenerationMediator.showBenchmarkingView();
  }

  /**
   * Displays the key generation  view in standard mode. This method updates the UI to present the
   * interface for standard key generation.
   */
  public void showGenViewStandard() {
    keyGenerationMediator.showStandardView();
  }

  /**
   * Displays the key generation  view in cross parameter benchmarking mode. This method updates the
   * UI to present the interface for benchmarking in comparison.
   */
  public void showGenViewCrossBenchmarking() {
    keyGenerationMediator.showCrossBenchmarkingView();
  }

  /**
   * Activates and configures the key generation controller for the custom comparison benchmarking
   * mode. This method instantiates a new GenControllerComparisonBenchmarking controller with custom
   * comparison logic and sets it as the current controller for comparison benchmarking operations
   * in the key generation mediator.
   *
   * @param genView The GenView instance that provides the user interface elements for the
   *                benchmarking mode.
   */
  public void activateKeyGenCustomComparisonMode(GenView genView) {
    keyGenerationMediator.setGenControllerComparisonBenchmarking(
        new GenControllerCustomComparisonBenchmarking(this), genView);
  }

  /**
   * Activates and configures the key generation controller for the comparison (provably secure vs
   * standard) benchmarking mode. This method instantiates a new GenControllerComparisonBenchmarking
   * controller with standard comparison logic and sets it as the current controller for comparison
   * benchmarking operations in the key generation mediator.
   *
   * @param genView The GenView instance that provides the user interface elements for the
   *                benchmarking mode.
   */
  public void activateKeyGenComparisonMode(GenView genView) {
    keyGenerationMediator.setGenControllerComparisonBenchmarking(
        new GenControllerComparisonBenchmarking(this), genView);
  }


}
