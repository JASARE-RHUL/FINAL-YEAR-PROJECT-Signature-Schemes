package uk.msci.project.rsa;

import java.io.IOException;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.stage.Stage;
import uk.msci.project.rsa.GenView;
import uk.msci.project.rsa.GenModel;
import uk.msci.project.rsa.MainController;
/**
 * This abstract class serves as the foundation for key generation controllers within the
 * application. It defines the basic structure and operations for key generation views while
 * allowing specific subclasses to implement the actual behavior for different operational modes
 * like standard, benchmarking, and cross-parameter benchmarking modes.
 */
public abstract class AbstractGenController {

  /**
   * The view component of the MVC pattern for the key generation functionality.
   */
  GenView genView;
  /**
   * The model component of the MVC pattern that handles the data and business logic for RSA key
   * generation
   */
  GenModel genModel;


  /**
   * The main controller that orchestrates the flow between different views of the application.
   */
  uk.msci.project.rsa.MainController mainController;


  /**
   * Constructs a GenController with a reference to the MainController.
   *
   * @param mainController The main controller that orchestrates the application flow.
   */
  public AbstractGenController(MainController mainController) {
    this.mainController = mainController;
  }

  /**
   * Displays the key generation view in standard mode.
   *
   * @param primaryStage The primary stage of the application where the view will be displayed.
   */
  void showStandardView(Stage primaryStage) {
    mainController.showGenViewStandard();
  }

  /**
   * Displays the key generation view in cross-parameter benchmarking mode. This method sets up the
   * interface and interactions necessary for the user to perform key generation with the ability to
   * compare results across different parameter sets.
   *
   * @param primaryStage The primary stage of the application where the view will be displayed.
   */
  void showCrossBenchmarkingView(Stage primaryStage) {
    mainController.showGenViewCrossBenchmarking();
  }

  /**
   * Initialises and displays the GenView for the key generation functionality in benchmarking mode.
   * This method loads the GenView FXML file, sets up the necessary model and view components, and
   * configures event handlers and observers for the various UI elements.
   *
   * @param primaryStage The primary stage of the application where the view will be displayed.
   */
  public void showBenchmarkingView(Stage primaryStage) {
    mainController.showGenViewBenchmarking();
  }


  /**
   * Loads the key generation view from the specified FXML file and sets up the view and model
   * components. This methods abstracts the common steps involved in loading and configuring
   * different variations of the GenView.
   *
   * @param fxmlPath      The path to the FXML file that contains the layout for the GenView.
   * @param observerSetup A Runnable containing additional setup steps for event handlers and
   *                      observers, specific to the particular GenView being loaded.
   */
  void loadGenView(String fxmlPath, Runnable observerSetup) {
    try {
      FXMLLoader loader = new FXMLLoader(getClass().getResource(fxmlPath));
      Parent root = loader.load();
      genView = loader.getController();
      this.genModel = new GenModel();
      genView.addBackToMainMenuObserver(new BackToMainMenuObserver());
      genView.addBenchmarkingModeToggleObserver(
          new ApplicationModeChangeObserver(AbstractGenController.this));
      observerSetup.run();

      mainController.setScene(root);
    } catch (IOException e) {
      e.printStackTrace();
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


  /**
   * Observer for changes in the application mode (Standard/Benchmarking). This class listens to
   * changes in the application mode toggle switch and updates the GenView accordingly. It switches
   * between the standard and benchmarking modes of the GenView based on the user's selection.
   */
  class ApplicationModeChangeObserver implements ChangeListener<Boolean> {

    private final AbstractGenController genController;

    public ApplicationModeChangeObserver(AbstractGenController genController) {
      this.genController = genController;
    }

    @Override
    public void changed(ObservableValue<? extends Boolean> observableValue, Boolean oldValue,
        Boolean newValue) {
      if (Boolean.TRUE.equals(newValue)) {
        if (Boolean.FALSE.equals(oldValue)) {
          genController.showBenchmarkingView(mainController.getPrimaryStage());
        }
      } else {
        if (Boolean.TRUE.equals(oldValue)) {
          genController.showStandardView(mainController.getPrimaryStage());
        }
      }
    }
  }

}
