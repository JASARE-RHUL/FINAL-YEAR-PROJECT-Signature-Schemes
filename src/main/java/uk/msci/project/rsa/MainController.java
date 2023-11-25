package uk.msci.project.rsa;


import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;
import java.io.IOException;

/**
 * This class serves as the central controller for the application, managing navigation between
 * different views and coordinating actions across the entire program.
 */
public class MainController {

  private Stage primaryStage;
  private MainMenuView mainMenuView;
  private GenController genController;
  private SignatureController signatureController;

  /**
   * Constructs a MainController with the primary stage of the application. This constructor
   * initializes the controller with the main application stage and displays the main menu view.
   *
   * @param primaryStage The primary stage of the application.
   */
  public MainController(Stage primaryStage) {
    this.primaryStage = primaryStage;

    // Initially show the MainMenuView
    showMainMenuView();
  }

  /**
   * Displays the main menu view on the primary stage. It loads the MainMenuView from the FXML file,
   * initialises its domain object, and sets it on the stage.
   */
  void showMainMenuView() {
    try {
      FXMLLoader loader = new FXMLLoader(
          getClass().getResource("MainMenuView.fxml"));
      Parent root = loader.load();
      mainMenuView = loader.getController();
      primaryStage.setScene(new Scene(root));
      primaryStage.show();
      mainMenuView.addGenerateKeysObserver(new GenerateKeysButtonObserver());
      mainMenuView.addSignDocumentObserver(new SignDocumentObserver());
      mainMenuView.addVerifySignatureObserver(new verifySignatureObserver());
    } catch (IOException e) {
      e.printStackTrace();
    }
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
   * Observes "Sign Document" button click. Instantiates the SignatureController and displays the
   * document signing view.
   */
  class SignDocumentObserver implements EventHandler<ActionEvent> {
    @Override
    public void handle(ActionEvent event) {
      signatureController = new SignatureController(MainController.this);
      signatureController.showSignView(primaryStage);
    }
  }


  class verifySignatureObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
      signatureController = new SignatureController(MainController.this);
      signatureController.showVerifyView(primaryStage);
    }
  }

}
