# Final Year Project

This project implements the Model-View-Controller (MVC) design pattern to ensure a clear separation
of concerns. The directory structure is customised to reflect this design principle and to
facilitate the implementation of the final application as described in the report.
Below is an overview of the structure and the Maven configuration used to accommodate it.

## Prerequisites

Java must be installed to run this application

## Demo Video

1. Full demo of the application:
2. Optional video (Recovering a partial message from a Signature (ISO\IEC 9796-2
   Scheme 1)):

## Running the application

To run the application, using the provided jar, run

```
java -jar digital-signature-benchmarking-1.0.jar
```

from the command line in the same directory that this README is contained in.

## Viewing javadoc

Code documentation in the form of javadoc can be found in the application/docs/apidocs directory.

```
Simply open `index.html` to view.
```

## Directory Structure

```bash
<Final Year Project>/
├── application/
│   ├── controllers/
│   │   └── LaunchMainMenu.java         # Orchestrates the application flow
│   │       └── MainController.java         # Central controller for the application
│   ├── models/ # Contains domain logic and data
│   │            
│   ├── views/
│   │       └── MainMenuView.java           # UI logic for the main menu
│   ├── utility/
│   │       └── FileHandle.java             # Utility class for file operations
│   ├── modules/
│   │   ├── key_generation/
│   │   │   ├── controllers/  # controller assembly for key generation
│   │   │   ├── models/ # Model assembly for key generation logic
│   │   │   ├── views/ # view assembly for key generation
│   │   │   ├── resources/   # FXML assembly for key generation views
│   │   │   └── tests/ # Unit tests for key generation module
│   │   ├──signatures/
│   │   │   ├── controllers/ # Controller assembly for signature processes
│   │   │   ├── models/ # Model assembly for signature logic
│   │   │   ├── views/ # view assembly for key generation
│   │   │   │       ├── SignatureBaseView.java  # Parent CLass
│   │   │   │       ├── SignView.java           # UI for signing process
│   │   │   │       └── VerifyView.java         # UI for verification process
│   │   │   ├── resources/ # FXML assembly for signature views
│   │   │   ├── utility/  # Utility classes for signatures module
│   │   │   └── tests/ # Unit tests for key generation module
│   │   └── Results/
│   │       ├── controllers/ # Controller assembly for results
│   │       ├── models/ # Model for results logic
│   │       ├── views/ # view for results
│   │       ├── resources/ # assembly for results view
│   │       └── tests/  # Unit tests for results module
│   ├── resources/
│   │   ├── MainMenuView.fxml                    # FXML for the main menu
│   │   └── checkmark.png                       # Resource image file
│   ├── docs/                                   # Documentation files
│   └── tests/     # integration tests for the application
└── ...
```

## Notes

- `application/` contains the full application, structured around the MVC pattern.
    - `controllers/, models/, and views/`: default controller, model or view directories.
    - `tests/` is used for storing the application test cases.
    - `docs/` directory is intended for project documentation.
    - `modules/`: Each application feature, such as key generation and signature processes, is
      self-contained within this directory. The structure under each module resembles the structure
      under the application directory.
    - `utility/`: Directory for utilities or common code that supports various application.
      functionalities.
    - `Resources`: Central repository for FXML files and static assets necessary for the views'
      visual components.

## MVC Pattern Context

The application level controllers directory contains the MainController, which acts as the
orchestrator, responding to user actions and coordinating the views linked to the specialised
modules.

- The models subdirectories within each module process the application data and contain the domain
  logic and data structures.
- The views manage the presentation layer, rendering content and notifying the controller of changes
  stemming from user interation.
- The controllers handle user input, observing changes in the view, manipulating the models and then
  updating the views.

## Application Modes Context

In the application, each MVC (Model-View-Controller) component for every module comprises an assembly of classes, each
designed for a specific application mode:

- **Standard Mode**: Classes like `GenModelStandard` (from the model assembly for key generation)
  and `GenControllerStandard` (from the controller assembly for key generation) are responsible for routine tasks like
  generating a single key or signature, without the complexity of benchmarking.

- **Benchmarking Mode**: Classes like `GenModelBenchmarking` and `GenControllerBenchmarking` specialize in processing
  and evaluating batches of operations, delivering results for individual keys.

- **Comparison Mode**: Comparison classes, such as `GenModelComparisonBenchmarking`
  and `GenControllerComparisonBenchmarking`, enable comparative analysis across different key sizes, contrasting
  parameters and outcomes side by side.

This pattern extends to the view assembly for key generation, as well as the respective assemblies for signatures
modules.

## Maven Configuration

The project uses Maven to manage the build lifecycle, with specific plugins configured to recognise
the multiple source and test directories in the build path. This allows the maintenance of a modular
structure and separation of domain concerns.

### Source Directories

The following additional source directories are configured:

- `application/models`
- `application/views`
- `application/controllers`
- `application/utility`
- `application/modules/key_generation/models`
- `application/modules/key_generation/views`
- `application/modules/key_generation/controllers`
- `application/modules/signatures/models`
- `application/modules/signatures/views`
- `application/modules/signatures/controllers`
- `application/modules/signatures/utility`
- `application/modules/results/models`
- `application/modules/results/views`
- `application/modules/results/controllers`

### Test Directories

The following additional test directories are configured:

- `application/tests`
- `application/modules/key_generation/tests`
- `application/modules/signatures/tests`

The top level application/tests directory houses integration tests.

### Resource Directories

Resources are configured to be included from the following directories:

- `application/resources`
- `application/modules/key_generation/resources`
- `application/modules/signatures/resources`
- `application/modules/results/resources`

---





