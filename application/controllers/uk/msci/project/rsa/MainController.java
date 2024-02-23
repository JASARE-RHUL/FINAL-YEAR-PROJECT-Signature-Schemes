package uk.msci.project.rsa;


import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.layout.Pane;
import javafx.stage.Stage;
import java.io.IOException;

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
   * Controller for the key generation functionality. This controller handles the logic related to
   * generating keys.
   */
  private GenController genController;

  /**
   * Controller for the signature verification functionality. Manages the logic and view related to
   * verifying digital signatures.
   */
  private SignatureVerificationController signatureVerificationController = new SignatureVerificationController(
      MainController.this);

  /**
   * Controller for the signature creation functionality. Handles the process of creating digital
   * signatures, typically by signing documents or messages.
   */
  private SignatureCreationController signatureCreationController = new SignatureCreationController(
      MainController.this);


  /**
   * Constructs a MainController with the primary stage of the application. This constructor
   * initializes the controller with the main application stage and displays the main menu view.
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
   * Gets the verification controller used to manage and operate signature verification related
   * functionalities
   *
   * @return The verification controller.
   */
  public SignatureVerificationController getSignatureVerificationController() {
    return signatureVerificationController;
  }

  /**
   * Gets the signature generation controller used to manage and operate signature generation
   * related functionalities
   *
   * @return The signature generation controller.
   */
  public SignatureCreationController getSignatureCreationController() {
    return signatureCreationController;
  }

  /**
   * Observers the "Generate Keys" button click. Instantiates the GenController and displays the key
   * generation view.
   */
  class GenerateKeysButtonObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
      genController = new GenController(MainController.this);
      genController.showGenView(primaryStage);
    }
  }

  /**
   * Observes "Sign Document" button click. Instantiates the SignatureCreationController and
   * displays the document signing view.
   */
  class SignDocumentObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
      signatureCreationController.showSignView(primaryStage);
    }
  }

  /**
   * Observes "verify signature" button click. Instantiates the SignatureVerificationController and
   * displays the signature verification view.
   */
  class verifySignatureObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
      signatureVerificationController.showVerifyView(primaryStage);
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
   * Sets a batch of private keys for signing operations. This method is used to provide the
   * SignatureCreationController with a batch of provably secure generated (small e ) private keys
   * to allow for later instantiation of  a signature scheme with provably secure parameters. The keys
   * can be set in comparison mode for production of results that enables provably secure
   * instantiations of scheme to be compared with standard instantiations.
   *
   * @param privateKeyBatch        The batch of private keys to be used for signing.
   * @param isKeyForComparisonMode If true, the keys are used in comparison mode for signing
   *                               operations.
   */
  public void setProvableKeyBatchForSigning(String privateKeyBatch,
      boolean isKeyForComparisonMode) {
    signatureCreationController.importKeyFromKeyGeneration(privateKeyBatch, isKeyForComparisonMode);
  }

  /**
   * Sets a batch of public keys for verification operations. This method is used to provide the
   * signatureVerificationController with a batch of provably secure generated (small e ) public
   * keys to allow for later instantiation of a signature scheme with provably secure parameters. The
   * keys can be set in comparison mode for production of results that enables provably secure
   * instantiations of scheme to be compared with standard instantiations.
   *
   * @param publicKeyBatch         The batch of public keys to be used for signature verification.
   * @param isKeyForComparisonMode If true, the keys are used in comparison mode for verification
   *                               operations.
   */
  public void setProvableKeyBatchForVerification(String publicKeyBatch,
      boolean isKeyForComparisonMode) {
    signatureVerificationController.importKeyFromKeyGeneration(publicKeyBatch,
        isKeyForComparisonMode);
  }


}
