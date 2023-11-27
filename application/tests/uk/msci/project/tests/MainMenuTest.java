package uk.msci.project.tests;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.testfx.api.FxAssert.verifyThat;

import javafx.scene.control.Button;
import javafx.scene.control.TextField;
import javafx.stage.Stage;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.testfx.api.FxRobot;
import org.testfx.framework.junit5.ApplicationExtension;
import org.testfx.framework.junit5.Start;
import org.testfx.matcher.control.LabeledMatchers;
import uk.msci.project.rsa.MainController;
import uk.msci.project.rsa.MainMenuView;

/**
 * Test class for MainMenuView UI interactions. Ensures that all buttons are present and correctly
 * labeled, and that navigation occurs as expected when buttons are clicked.
 */
@ExtendWith(ApplicationExtension.class)
public class MainMenuTest {

  private MainMenuView mainMenuView;

  /**
   * Initializes the test fixture with the main stage.
   *
   * @param stage The primary stage for this application.
   * @throws Exception if initialization fails
   */
  @Start
  public void start(Stage stage) throws Exception {
    MainController mainController = new MainController(stage);

  }

  /**
   * Tests that the Generate Keys button exists and is correctly labeled.
   *
   * @param robot The robot used to simulate user interactions.
   */
  @Test
  public void testGenerateKeysButton(FxRobot robot) {
    Button node = (Button) robot.lookup("#generateKeysButton").query();
    assertNotNull(node, "The component should exist.");
    // Verify that the button with the text "[K] Generate Keys" is present
    verifyThat("#generateKeysButton", LabeledMatchers.hasText("[K] Generate Keys"));
  }

  /**
   * Tests the navigation functionality of the Generate Keys button works as intended by confirming
   * that the key generation view is successfully loaded.
   *
   * @param robot The robot used to simulate user interactions.
   */
  @Test
  public void testGenerateKeysButtonNavigation(FxRobot robot) {
    // Click the "[K] Generate Keys" button
    robot.clickOn("#generateKeysButton");
    TextField node = (TextField) robot.lookup("#keySizeTextField").query();
    assertNotNull(node, "The component should exist.");
  }

  /**
   * Tests that the Sign Document button exists and is correctly labeled.
   *
   * @param robot The robot used to simulate user interactions.
   */
  @Test
  public void testSignDocumentButton(FxRobot robot) {
    Button node = (Button) robot.lookup("#signDocumentButton").query();
    assertNotNull(node, "The component should exist.");
    verifyThat("#signDocumentButton", LabeledMatchers.hasText("[S] Sign Document"));
  }

  /**
   * Tests the navigation functionality of the Sign Document button. orks as intended by confirming
   * that the sign view is successfully loaded.
   *
   * @param robot The robot used to simulate user interactions.
   */
  @Test
  public void testSignDocumentButtonNavigation(FxRobot robot) {
    robot.clickOn("#signDocumentButton");
    Button node = (Button) robot.lookup("#createSignatureButton").query();
    assertNotNull(node, "The component should exist.");
    verifyThat("#createSignatureButton", LabeledMatchers.hasText("Create Signature"));
  }

  /**
   * Tests that the Verify Signature button exists and is correctly labeled.
   *
   * @param robot The robot used to simulate user interactions.
   */
  @Test
  public void testVerifySignatureButton(FxRobot robot) {
    Button node = (Button) robot.lookup("#verifySignatureButton").query();
    assertNotNull(node, "The component should exist.");
    verifyThat("#verifySignatureButton", LabeledMatchers.hasText("[V] Verify Signature"));
  }

  /**
   * Tests the navigation functionality of the Verify Signature button works as intended by
   * confirming that the verify view is successfully loaded.
   *
   * @param robot The robot used to simulate user interactions.
   */
  @Test
  public void testVerifySignatureButtonNavigation(FxRobot robot) {
    robot.clickOn("#verifySignatureButton");
    Button node = (Button) robot.lookup("#verifyBtn").query();
    assertNotNull(node, "The component should exist.");
    verifyThat("#verifyBtn", LabeledMatchers.hasText("Verify Signature"));
  }

}
