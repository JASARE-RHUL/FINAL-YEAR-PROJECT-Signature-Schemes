package uk.msci.project.rsa;

import java.io.IOException;
import java.util.regex.Pattern;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;
import javafx.stage.Stage;

/**
 * Controller class for the key generation view in the digital signature application. It handles
 * user interactions related to generating keys and communicates with the GenModel to perform the
 * actual key generation logic.
 */
public class GenController {

  /**
   * The view component of the MVC pattern for the key generation functionality.
   */
  private GenView genView;
  /**
   * The model component of the MVC pattern that handles the data and business logic for RSA key
   * generation
   */
  private GenModel genModel;
  /**
   * The main controller that orchestrates the flow between different views of the application.
   */
  private MainController mainController;

  /**
   * Constructs a GenController with a reference to the MainController.
   *
   * @param mainController The main controller that orchestrates the application flow.
   */
  public GenController(MainController mainController) {
    this.mainController = mainController;
  }

  /**
   * Initialises and displays the GenView to the user.
   *
   * @param primaryStage The primary stage for the application.
   */
  public void showGenView(Stage primaryStage) {
    try {
      FXMLLoader loader = new FXMLLoader(getClass().getResource("/GenView.fxml")); // Update path
      Parent root = loader.load();
      genView = loader.getController();
      genModel = new GenModel();
      // Add observers for buttons or other actions
      genView.addGenerateButtonObserver(new GenerateKeyObserver());
      genView.addBackToMainMenuObserver(new BackToMainMenuObserver());
      genView.addHelpObserver(new BackToMainMenuObserver());

      primaryStage.setScene(new Scene(root));

    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  /**
   * Observer that observes the potential event of the generate key button being selected. I It
   * validates the input and triggers key generation in the model.
   */
  class GenerateKeyObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
      String keyBitSizes = genView.getKeySize();
      if (!(Pattern.compile("^\\s*\\d+\\s*(,\\s*\\d+\\s*)*$").matcher(genView.getKeySize())
          .matches())) {
        genView.setFailureLabel(
            "Failure. Please ensure your input is comma separated sequence of bit sizes "
                + "corresponding to the number of prime factors you wish the modulus to contain.");
        genView.setSuccessPopupVisible(false);
        genView.setFailurePopupVisible(true);

      } else {

        String[] numberStrings = keyBitSizes.split("\\s*,\\s*");
        int[] intArray = new int[numberStrings.length];
        Alert alert = new Alert(AlertType.INFORMATION);
        int k = numberStrings.length;
        for (int i = 0; i < k; i++) {
          // if number is too big to parse as Integer
          // pass, use a bit size larger than the maximum bit size
          // to cause the process to fail
          try {
            intArray[i] = Integer.parseInt(numberStrings[i]);
          } catch (NumberFormatException e) {
            intArray[i] = 8000;
          }
        }
        genModel.setKeyParameters(k, intArray);
        try {
          genModel.setGen();
        } catch (IllegalArgumentException e) {
          genView.setFailureLabel(
              "Failure. Please ensure you have entered at least two bit sizes and that the sum of your "
                  + "bit-sizes is not smaller than 1024 bits or larger than 7192 bits.");
          genView.setSuccessPopupVisible(false);
          genView.setFailurePopupVisible(true);
          return;
        }
        genModel.generateKey();
        genView.setFailurePopupVisible(false);
        genView.setSuccessPopupVisible(true);
        genView.addExportPublicKeyObserver(new ExportPublicKeyObserver());
        genView.addExportPrivateKeyObserver(new ExportPrivateKeyObserver());

      }
    }
  }

  /**
   * Observer for exporting the generated public key. It calls the model to save the public key to a
   * file.
   */
  class ExportPublicKeyObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
      try {
        genModel.getGeneratedKeyPair().getPublicKey().exportKey("publicKey.rsa");
        uk.msci.project.rsa.DisplayUtility.showInfoAlert("Export",
            "The public key was successfully exported!");

      } catch (IOException e) {
        e.printStackTrace();
      }
    }
  }

  /**
   * Observer for exporting the generated private key. It calls the model to save the private key to
   * a file.
   */
  class ExportPrivateKeyObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
      try {
        genModel.getGeneratedKeyPair().getPrivateKey().exportKey("key.rsa");
        uk.msci.project.rsa.DisplayUtility.showInfoAlert("Export",
            "The private key was successfully exported!");
      } catch (IOException e) {
        e.printStackTrace();
      }
    }
  }

  /**
   * The observer for returning to the main menu. This class handles the action event triggered when
   * the user wishes to return to the main menu from the signature view.
   */
  class BackToMainMenuObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
      mainController.showMainMenuView();
      genModel = null;
      genView = null;
    }
  }


}
