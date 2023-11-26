# Final Year Project

This project implements the Model-View-Controller (MVC) design pattern to ensure a clear separation
of concerns. The directory structure is customised to reflect this design principle and to
facilitate the implementation of the Proof of Concept (PoC) program as described in the report.
Below is an overview of the structure and the Maven configuration used to accommodate it.

## Directory Structure

```bash
<Final Year Project>/
├── application/
│   ├── controllers/
│   │   └── uk.msci.project.rsa/
│   │       ├── LaunchMainMenu.java         # Orchestrates the application flow
│   │       └── MainController.java         # Central controller for the application
│   ├── models/
│   │   └── uk.msci.project.rsa/            # Contains domain logic and data
│   ├── views/
│   │   └── uk.msci.project.rsa/
│   │       └── MainMenuView.java           # UI logic for the main menu
│   ├── utility/
│   │   └── uk.msci.project.rsa/
│   │       └── FileHandle.java             # Utility class for file operations
│   ├── modules/
│   │   ├── key_generation/
│   │   │   ├── controllers/
│   │   │   │   └── uk.msci.project.rsa/
│   │   │   │       └── GenController.java  # Controller for key generation
│   │   │   ├── models/
│   │   │   │   └── uk.msci.project.rsa/
│   │   │   │       └── GenModel.java       # Model for key generation logic
│   │   │   ├── views/
│   │   │   │   └── uk.msci.project.rsa/
│   │   │   │       └── GenView.java        # UI logic for key generation
│   │   │   ├── resources/
│   │   │   │   └── GenView.fxml             # FXML for key generation view
│   │   │   └── tests/
│   │   │       └── uk.msci.project.tests/  # Unit tests for key generation module
│   │   └── signatures/
│   │       ├── controllers/
│   │       │   └── uk.msci.project.rsa/
│   │       │       └── SignatureController.java  # Controller for signature processes
│   │       ├── models/
│   │       │   └── uk.msci.project.rsa/
│   │       │       └── SignatureModel.java     # Model for signature logic
│   │       ├── views/
│   │       │   └── uk.msci.project.rsa/
│   │       │       ├── SignView.java           # UI for signing process
│   │       │       └── VerifyView.java         # UI for verification process
│   │       ├── resources/
│   │       │   ├── SignView.fxml                # FXML for signing view
│   │       │   └── VerifyView.fxml              # FXML for verification view
│   │       ├── utility/
│   │       │   └── uk.msci.project.rsa/        # Utility classes for signatures module
│   │       └── tests/
│   │           └── uk.msci.project.tests/      # Unit tests for signatures module
│   ├── resources/
│   │   ├── MainMenuView.fxml                    # FXML for the main menu
│   │   └── checkmark.png                       # Resource image file
│   ├── docs/                                   # Documentation files
│   └── tests/
│       └── uk.msci.project.tests/              # Unit tests for the application
└── ...
```

## Notes

- `application/` contains the full application structured around the MVC pattern.
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

### Test Directories

The following additional test directories are configured:

- `application/tests`
- `application/modules/key_generation/tests`
- `application/modules/signatures/tests`

### Resource Directories

Resources are configured to be included from the following directories:

- `application/resources`
- `application/modules/key_generation/resources`
- `application/modules/signatures/resources`

---





