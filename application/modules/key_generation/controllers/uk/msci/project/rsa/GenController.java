package uk.msci.project.rsa;

import static uk.msci.project.rsa.KeyGenUtil.convertStringToIntArray;

import java.io.IOException;
import java.util.List;
import java.util.regex.Pattern;
import javafx.application.Platform;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.concurrent.Task;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.ButtonType;
import javafx.scene.control.Dialog;
import javafx.scene.control.Label;
import javafx.scene.control.ProgressBar;
import javafx.scene.control.RadioButton;
import javafx.scene.control.Toggle;
import javafx.stage.Stage;
import javafx.util.Pair;

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
   * The number of trials a tracked benchmarking session should last for
   */
  private int numTrials;


  /**
   * Constructs a GenController with a reference to the MainController.
   *
   * @param mainController The main controller that orchestrates the application flow.
   */
  public GenController(MainController mainController) {
    this.mainController = mainController;
  }

  /**
   * Initialises and displays the GenView for the key generation functionality in benchmarking mode.
   * This method loads the GenView FXML file, sets up the necessary model and view components, and
   * configures event handlers and observers for the various UI elements.
   *
   * @param primaryStage The primary stage of the application where the view will be displayed.
   */
  public void showGenView(Stage primaryStage) {
    try {

      FXMLLoader loader = new FXMLLoader(getClass().getResource("/GenView.fxml"));
      Parent root = loader.load();
      genView = loader.getController();
      genModel = new GenModel();

      genView.addBackToMainMenuObserver(new BackToMainMenuObserver());
      genView.addHelpObserver(new BackToMainMenuObserver());
      genView.addNumKeysObserver(new NumKeysBtnObserver());
      genView.addBenchmarkingModeToggleObserver(new ApplicationModeChangeObserver());
      genView.addCrossBenchMarkingToggleGroupChangeObserver(new ComparisonModeChangeObserver());

      mainController.setScene(root);

    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  /**
   * Initialises and displays the GenView in standard mode. Similar to showGenView, this method sets
   * up the GenView for the standard key generation mode. It excludes elements and observers
   * specific to benchmarking mode and sets up the UI for standard key generation.
   *
   * @param primaryStage The primary stage of the application where the view will be displayed.
   */
  public void showGenViewStandardMode(Stage primaryStage) {
    try {
      FXMLLoader loader = new FXMLLoader(getClass().getResource("/GenViewStandardMode.fxml"));
      Parent root = loader.load();
      genView = loader.getController();
      genModel = new GenModel();
      // Add observers for buttons or other actions

      genView.addBackToMainMenuObserver(new BackToMainMenuObserver());
      genView.addHelpObserver(new BackToMainMenuObserver());
      genView.addGenerateButtonObserver(new GenerateKeyObserver());
      genView.addBenchmarkingModeToggleObserver(new ApplicationModeChangeObserver());

      mainController.setScene(root);


    } catch (IOException e) {
      e.printStackTrace();
    }
  }


  /**
   * Observer that observes the potential event of the generate key button being selected. It
   * validates the input and triggers key generation in the model.
   */
  class GenerateKeyObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
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
        boolean isSmallE;
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
        mainController.setProvableKeyForSignatureProcesses(
            genModel.getGeneratedKeyPair().getPrivateKey().getKeyValue(),
            genModel.getGeneratedKeyPair().getPublicKey().getKeyValue());
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
   * Observer that handles the event of generating a batch of keys based on user input. It processes
   * the number of keys and their respective parameters, and initiates a benchmarking task to
   * generate the keys and calculate statistics.
   */
  class NumKeysBtnObserver implements EventHandler<ActionEvent> {

    @Override
    public void handle(ActionEvent event) {
      int numKeys = 0;
      try {
        numKeys = Integer.parseInt(genView.getNumKeys());
      } catch (NumberFormatException e) {
        uk.msci.project.rsa.DisplayUtility.showErrorAlert(
            "Error: Invalid input. Please enter a valid number of keys.");
        return;
      }
      if (genView.getCrossBenchMarkingToggle().equals("Yes")) {
        handleBenchmarkingInitiationComparisonMode(numKeys);
        return;
      }
      // Show the dynamic fields dialog and check if it was completed successfully
      boolean isFieldsDialogCompleted = genView.showDynamicFieldsDialog(numKeys,
          mainController.getPrimaryStage());
      if (isFieldsDialogCompleted) {
        // Only proceed to show the trials dialog if the fields dialog was completed
        if (genView.showTrialsDialog(mainController.getPrimaryStage())) {
          numTrials = genView.getNumTrials();

          // Show the progress dialog
          Dialog<Void> progressDialog = uk.msci.project.rsa.DisplayUtility.showProgressDialog(
              mainController.getPrimaryStage(), "Key Generation");
          ProgressBar progressBar = (ProgressBar) progressDialog.getDialogPane()
              .lookup("#progressBar");
          Label progressLabel = (Label) progressDialog.getDialogPane().lookup("#progressLabel");

          Task<Void> benchmarkingTask = createBenchmarkingTask(numTrials,
              genView.getDynamicKeyData(),
              progressBar, progressLabel);
          new Thread(benchmarkingTask).start();

          progressDialog.getDialogPane().lookupButton(ButtonType.CANCEL)
              .addEventFilter(ActionEvent.ACTION, e -> {
                if (benchmarkingTask.isRunning()) {
                  benchmarkingTask.cancel();
                }
              });

          benchmarkingTask.setOnSucceeded(e -> {
            progressDialog.close();
            handleBenchmarkingCompletion(); // Handle completion
          });

          benchmarkingTask.setOnFailed(e -> {
            progressDialog.close();
            uk.msci.project.rsa.DisplayUtility.showErrorAlert(
                "Error: Benchmarking failed. Please try again.");

          });
        }
      }
    }
  }

  /**
   * Handles the completion of the benchmarking task for key generation in comparison mode. This
   * method is called when the benchmarking task successfully completes. It initialises and sets up
   * the ResultsController with the appropriate context and displays the results view with the
   * gathered benchmarking data.
   */
  private void handleBenchmarkingCompletionComparisonMode() {
    ResultsController resultsController = new ResultsController(mainController);
    BenchmarkingContext context = new KeyGenerationContext(genModel);
    resultsController.setContext(context);
    genModel.generateKeyBatch();
    mainController.setProvableKeyBatchForSigning(genModel.getPrivateKeyBatch(), true);
    mainController.setProvableKeyBatchForVerification(genModel.getPublicKeyBatch(), true);
    resultsController.showResultsView(mainController.getPrimaryStage(),
        genModel.getClockTimesPerTrial(), genModel.summedKeySizes(genModel.getKeyParams()), true,
        genModel.getNumKeySizesForComparisonMode());
  }

  /**
   * Handles the initiation of benchmarking in comparison mode. This method sets up and shows the
   * dynamic fields dialog for comparison mode, and if completed successfully, proceeds to show the
   * trials dialog and initiate the benchmarking task.
   *
   * @param numKeys The number of key sizes specified by the user for the comparison benchmarking.
   */
  private void handleBenchmarkingInitiationComparisonMode(int numKeys) {
    // Show the dynamic fields dialog and check if it was completed successfully
    boolean isFieldsDialogCompleted = genView.showDynamicFieldsDialogComparisonMode(numKeys,
        mainController.getPrimaryStage());
    if (isFieldsDialogCompleted) {
      // Only proceed to show the trials dialog if the fields dialog was completed
      if (genView.showTrialsDialog(mainController.getPrimaryStage())) {
        numTrials = genView.getNumTrials();

        // Show the progress dialog
        Dialog<Void> progressDialog = uk.msci.project.rsa.DisplayUtility.showProgressDialog(
            mainController.getPrimaryStage(), "Key Generation");
        ProgressBar progressBar = (ProgressBar) progressDialog.getDialogPane()
            .lookup("#progressBar");
        Label progressLabel = (Label) progressDialog.getDialogPane().lookup("#progressLabel");

        Task<Void> benchmarkingTask = createBenchmarkingTaskComparisonMode(
            genView.getDynamicKeySizeData(), numTrials,
            progressBar, progressLabel);
        new Thread(benchmarkingTask).start();

        progressDialog.getDialogPane().lookupButton(ButtonType.CANCEL)
            .addEventFilter(ActionEvent.ACTION, e -> {
              if (benchmarkingTask.isRunning()) {
                benchmarkingTask.cancel();
              }
            });

        benchmarkingTask.setOnSucceeded(e -> {
          progressDialog.close();
          handleBenchmarkingCompletionComparisonMode(); // Handle completion
        });

        benchmarkingTask.setOnFailed(e -> {
          progressDialog.close();
          uk.msci.project.rsa.DisplayUtility.showErrorAlert(
              "Error: Benchmarking failed. Please try again.");

        });
      }
    }
  }


  /**
   * Handles the completion of the benchmarking task for key generation. This method is called when
   * the benchmarking task successfully completes. It initialises and sets up the ResultsController
   * with the appropriate context (KeyGenerationContext) and displays the results view with the
   * gathered benchmarking data.
   */
  private void handleBenchmarkingCompletion() {
    ResultsController resultsController = new ResultsController(mainController);
    BenchmarkingContext context = new KeyGenerationContext(genModel);
    resultsController.setContext(context);
    genModel.generateKeyBatch();
    if (genModel.generateKeyBatch()) {
      mainController.setProvableKeyBatchForSigning(genModel.getPrivateKeyBatch(), false);
      mainController.setProvableKeyBatchForVerification(genModel.getPublicKeyBatch(), false);
    }
    resultsController.showResultsView(mainController.getPrimaryStage(),
        genModel.getClockTimesPerTrial(), genModel.summedKeySizes(genModel.getKeyParams()));
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

  /**
   * Creates a background task for benchmarking key generation. This task generates keys based on
   * provided parameters and updates the progress bar and label on the UI.
   *
   * @param numTrials     The number of trials for key generation.
   * @param keyParams     The parameters for key generation, including bit sizes and the small e
   *                      option.
   * @param progressBar   The ProgressBar to update with progress information.
   * @param progressLabel The Label to update with progress information.
   * @return A Task to execute the benchmarking process in the background.
   */
  private Task<Void> createBenchmarkingTask(int numTrials, List<Pair<int[], Boolean>> keyParams,
      ProgressBar progressBar, Label progressLabel) {
    return new Task<>() {
      @Override
      protected Void call() throws Exception {
        genModel.batchGenerateKeys(numTrials, keyParams, progress -> Platform.runLater(() -> {
          progressBar.setProgress(progress);
          progressLabel.setText(String.format("%.0f%%", progress * 100));
        }));
        return null;
      }
    };

  }

  /**
   * Creates a background task for benchmarking key generation in comparison mode. This task
   * generates keys based on provided key sizes and updates the progress bar and label on the UI.
   *
   * @param keyParams     The list of key sizes for which keys are to be generated.
   * @param numTrials     The number of trials for key generation.
   * @param progressBar   The ProgressBar to update with progress information.
   * @param progressLabel The Label to update with progress information.
   * @return A Task to execute the benchmarking process in the background.
   */
  private Task<Void> createBenchmarkingTaskComparisonMode(List<Integer> keyParams, int numTrials,
      ProgressBar progressBar, Label progressLabel) {
    return new Task<>() {
      @Override
      protected Void call() throws Exception {
        genModel.batchGenerateInComparisonMode(keyParams, numTrials,
            progress -> Platform.runLater(() -> {
              progressBar.setProgress(progress);
              progressLabel.setText(String.format("%.0f%%", progress * 100));
            }));
        return null;
      }
    };

  }


  /**
   * Observer for changes in the application mode (Standard/Benchmarking). This class listens to
   * changes in the application mode toggle switch and updates the GenView accordingly. It switches
   * between the standard and benchmarking modes of the GenView based on the user's selection.
   */
  class ApplicationModeChangeObserver implements ChangeListener<Boolean> {

    @Override
    public void changed(ObservableValue<? extends Boolean> observableValue, Boolean oldValue,
        Boolean newValue) {
      if (Boolean.TRUE.equals(newValue)) {
        if (Boolean.FALSE.equals(oldValue)) {
          showGenView(mainController.getPrimaryStage());
        }
      } else {
        if (Boolean.TRUE.equals(oldValue)) {
          showGenViewStandardMode(mainController.getPrimaryStage());
        }
      }
    }
  }

  /**
   * Observer for selecting the comparison mode in the GenView. This class listens to changes in the
   * comparison mode toggle group and updates the GenView UI elements based on the selected mode.
   */
  class ComparisonModeChangeObserver implements ChangeListener<Toggle> {

    @Override
    public void changed(ObservableValue<? extends Toggle> observable, Toggle oldValue,
        Toggle newValue) {
      if (newValue != null) {
        RadioButton selectedRadioButton = (RadioButton) newValue;
        String radioButtonText = selectedRadioButton.getText();
        switch (radioButtonText) {
          case "Yes":
            genView.setNumKeySizesLabelVisibility(true);
            genView.setNumKeysLabelVisibility(false);
            break;
          case "No":
            genView.setNumKeySizesLabelVisibility(false);
            genView.setNumKeysLabelVisibility(true);
          default:
            break;

        }
      }
    }
  }


}
