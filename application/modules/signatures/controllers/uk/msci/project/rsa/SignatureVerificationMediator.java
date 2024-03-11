package uk.msci.project.rsa;

/**
 * SignatureVerificationMediator extends the functionality of SignatureMediator specifically for
 * signature verification processes. This class handles the initialisation and management of
 * signature verification controllers for both standard and benchmarking modes. It ensures the
 * application utilises the appropriate controller for signature verification based on the current
 * operational context and mode.
 */
public class SignatureVerificationMediator extends SignatureMediator {

  /**
   * Constructs a SignatureVerificationMediator with a reference to the main controller of the
   * application. It initialises the standard and benchmarking mode controllers for signature
   * verification.
   *
   * @param mainController The main controller of the application, responsible for overall
   *                       application flow.
   */
  public SignatureVerificationMediator(MainController mainController) {
    super(mainController);
    this.signatureControllerStandard = new SignatureVerificationControllerStandard(mainController);
    this.signatureControllerBenchmarking = new SignatureVerificationControllerBenchmarking(
        mainController);
    this.signatureControllerComparisonBenchmarking = new SignatureVerificationControllerComparisonBenchmarking(
        mainController);
  }

}
