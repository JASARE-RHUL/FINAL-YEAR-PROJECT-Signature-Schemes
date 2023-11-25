package uk.msci.project.rsa;

import javafx.application.Application;
import javafx.stage.Stage;

public class LaunchMainMenu extends Application {

  @Override
  public void start(Stage primaryStage) {
    MainController mainController = new MainController(primaryStage);
  }

  public static void main(String[] args) {
    launch(args);
  }
}
