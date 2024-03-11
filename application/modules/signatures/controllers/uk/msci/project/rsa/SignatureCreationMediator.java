package uk.msci.project.rsa;

/**
 * SignatureCreationMediator extends the functionality of SignatureMediator specifically for
 * signature creation processes. It initialises and manages signature creation controllers for both
 * standard and benchmarking modes, ensuring the correct controller is used based on the operational
 * context and mode of the application.
 */
public class SignatureCreationMediator extends SignatureMediator {

  /**
   * Constructs a SignatureCreationMediator with a reference to the main controller of the
   * application. Initialises the standard and benchmarking mode controllers for signature
   * creation.
   *
   * @param mainController The main controller of the application, orchestrating overall flow.
   */
  public SignatureCreationMediator(MainController mainController) {
    super(mainController);
    this.signatureControllerStandard = new SignatureCreationControllerStandard(mainController);
    this.signatureControllerBenchmarking = new SignatureCreationControllerBenchmarking(
        mainController);
    this.signatureControllerComparisonBenchmarking = new SignatureCreationControllerComparisonBenchmarking(
        mainController);
  }

}
