package uk.msci.project.rsa;

import javafx.application.Application;
import javafx.stage.Stage;
import uk.msci.project.rsa.MainController;

/**
 * Entry point for a JavaFX application that initializes and displays the
 * main menu. This class
 * extends the Application class from JavaFX and overrides the start method
 * to set up the primary
 * stage of the application.
 */
public class LaunchMainMenu extends Application {

  /**
   * Initialises the mainController that launched the Digital Signature Program.
   */
  @Override
  public void start(Stage primaryStage) {
    MainController mainController = new MainController(primaryStage);
  }

  /**
   * The main entry point for all JavaFX applications. The launch method is
   * called to start the
   * application.
   *
   * @param args Command line arguments passed to the application.
   */
  public static void main(String[] args) {
    launch(args);
  }
}
