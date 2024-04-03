package uk.msci.project.rsa;

import static uk.msci.project.rsa.KeyGenUtil.convertStringToIntArray;

import java.io.IOException;
import java.util.regex.Pattern;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.stage.Stage;
import uk.msci.project.rsa.AbstractGenController;
import uk.msci.project.rsa.MainController;
import uk.msci.project.rsa.GenModel;

/**
 * Controller class for the key generation view in the digital signature application. It handles
 * user interactions related to generating keys and communicates with the GenModel to perform the
 * actual key generation logic.
 */
public class GenControllerStandard extends AbstractGenController {


  /**
   * Constructs a GenController with a reference to the MainController.
   *
   * @param mainController The main controller that orchestrates the application flow.
   */
  public GenControllerStandard(MainController mainController) {
    super(mainController);
  }


  /**
   * Initialises and displays the GenView in standard mode. Similar to showGenView, this method sets
   * up the GenView for the standard key generation mode. It excludes elements and observers
   * specific to benchmarking mode and sets up the UI for standard key generation.
   *
   * @param primaryStage The primary stage of the application where the view will be displayed.
   */
  public void showStandardView(Stage primaryStage) {
    genModel = new GenModel();
    loadGenView("/GenViewStandardMode.fxml", () -> {
    });
    genView.addGenerateButtonObserver(new GenerateKeyObserver());
  }

  /**
   * Observer that observes the potential event of the generate key button being selected. It
   * validates the input and triggers key generation in the model.
   */
  class GenerateKeyObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
      boolean isSmallE;
      String keyBitSizes = genView.getKeySize();
      if (!(Pattern.compile("^\\s*\\d+(?:\\s*,\\s*\\d+)+\\s*$").matcher(genView.getKeySize())
          .matches())) {
        uk.msci.project.rsa.DisplayUtility.showErrorAlert(
            "Failure. Please ensure your input is comma separated sequence of bit sizes "
                + "corresponding to the number of prime factors you wish the modulus to contain.");

        genView.setSuccessPopupVisible(false);
      } else {
        int[] intArray = convertStringToIntArray(keyBitSizes);
        int k = intArray.length;

        genModel.setKeyParameters(k, convertStringToIntArray(keyBitSizes));
        try {
          isSmallE = genView.getSmallEToggle().equals("Yes");
          genModel.setGen(isSmallE);
        } catch (IllegalArgumentException e) {
          uk.msci.project.rsa.DisplayUtility.showErrorAlert(
              "Failure. Please ensure your input is comma separated sequence of bit sizes "
                  + "corresponding to the number of prime factors you wish the modulus to contain.");
          genView.setSuccessPopupVisible(false);
          return;
        }
        genModel.generateKey();
        if (isSmallE) {
          mainController.setProvableKeyForSignatureProcesses(
              genModel.getGeneratedKeyPair().getPrivateKey().getKeyValue(),
              genModel.getGeneratedKeyPair().getPublicKey().getKeyValue());
        }
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


}
