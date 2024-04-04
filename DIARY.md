# Diary

## Diary Entry: Week of 18th - 24th September 2023

This week was dedicated to writing a first draft of the abstract for my project (PKCS signature
scheme) and researching arbitrary precision arithmetic for a library I may look to implement as part
of the aims for the project On Monday, I started writing about its importance, touching on its
widespread use and history. Tuesday was a continuation, emphasising why it’s such a vital system.

By Wednesday, I added details on potential security issues, particularly focusing on something
called the Bleichenbaucher attacks. I was initially puzzled about how these attacks affected the
signature scheme.

On Thursday and Friday, after more research, I figured out the difference between how these attacks
affect encryption and signature aspects of the system. This helped clarify some of my earlier
confusion.

Over the weekend, I added insights on why, despite some concerns, many still prefer the PKCS system.
I also touched upon a new research finding that supports its use. By Sunday, I detailed my main
goals for this project, hoping to create a useful tool that compares different signature schemes.

Next I will clarify whether I should consider implementing a self-made big number library as part of
the project and hopefully advance significantly in the creation of the project plan.

## Diary Entry - Week of 25th September - 1st October 2023

Met with supervisor for initial meeting. Discussed potential extensions to the original project
specifications and in general what the project entails. Refocused and refined the project plan,
emphasising deterministic RSA hash-and-sign schemes, especially PKCS#1 v1.5. Made structural changes
to the introduction and abstract, enhancing clarity. Set up the Maven project directory on GitLab
and further developed the project timeline. Transitioned all documentation from Microsoft Word to
latex, drafting the literature review in the process. By week's end, automated referencing in latex
for enhanced efficiency.

## Diary Entry - Week of 2nd October - 8th October 2023

This week, I refined and expanded the Risks and mitigation section, established a risk
quantification table, and deepened my understanding of digital signature schemes. The literature
review for the interim report was integrated, and significant progress was made in drafting the
cryptographic foundation of the report. By the weekend, focus was channeled into classifying digital
signature schemes and laying out a clear structure for detailed exploration of specific signature
schemes in upcoming sessions. Next I will begin writing the introductory section on digital
signatures for my report.

## Diary Entry - Week of 9th October - 15th October 2023

I Started the week with supervisor meeting, confirming my focus on the POC PKCS Signature for term 1
and was given advise to potentially using the top 1000 English words for the signature program when
I sought guidance on the type of data I could provide to be signed. I delved into textbook RSA,
highlighting its vulnerabilities. By Friday, I had expanded on RSA's role in digital signatures,
introducing potential attacks and Hashed RSA signatures. The weekend saw me laying the foundation
for all three schemes considered in the project by formally defining them. I then began to explore
the motivation of provably secure signature schemes.

## Diary Entry - Week of 16th October - 22nd October 2023

I started the week attempting to try and understanding trapdoor permutations, especially how they
tie into RSA. Following this I began work on enumerating the requirements for the proof of concept
program. By the end Friday, I had detailed the user stories and actors for the program with a
corresponding a UML use case diagram. During the weekend I first focussed on expanding the
motivation for provable security section with subsections on real world implications and
limitations. I finished off the week on Sunday by trimming down the report to make it more concise.

## Diary Entry - Week of 23rd October - 29th October 2023

The week started with a meeting where I received constructive feedback on my project plan,
specifically that I had spent too much time on PKCS#1 v1.5 encryption scheme and Bleichenbacher
attacks, which were deemed beyond the project’s scope. We clarified the implications of the interim
report's word limit, and I was reassured that my report’s structure was on the right track, though I
was advised against including full software design documents.

I primarily focused on refining my project plan based on feedback. After restructuring my report and
creating an appendix for the software requirements of the proof of concept program, I turned my
attention to conceptualising and beginning the implementation of the RSA key generation process,
culminating in a complete first draft by Friday. The weekend was dedicated to initiating a new
chapter on security proof in the report, laying down the foundational concepts and starting to weave
them into the project's larger narrative.

## Diary Entry - Week of 30th October - 5th November 2023

Focused on enhancing the clarity and structure of my project report, I began by unifying the
background concepts for security proofs. I refined the introduction, dividing it into clear aims and
objectives. I then pruned excess information from several sections for brevity and clarity,
particularly around RSA concepts. I started work on the design phase for the proof of concept
program kicking off with a draft outline of the MVC architecture and factory patterns, which I later
formalised into a UML class diagram. By the week's end, I finalised design diagrams, integrated them
into the report, and refined the section on provable security. The upcoming weeks are now poised for
the implementation stage.

## Diary Entry - Week of 6th November - 12th November 2023

This week, I had the 4th meeting with my supervisor, where we clarified the required content for the
security proofs in my report, focusing on the practical implications for the signature schemes. My
progress on the interim report was positively noted, and I announced my intention to submit a draft
shortly. I began conceptualising (Wednesday) and then coding the PKCS#1 v1.5 signature scheme (
Thursday) with a focus on modularity. By the end of the week, I had not only implemented this scheme
but also completed the security proof chapter of my report, emphasising the implications for
practical parameter choices. I also improved the key generation process to be more parametrisable,
setting a foundation for term 2 work where this is required.

## Diary Entry - Week of 13th November - 19th November 2023

This week, I focused on implementing various signature schemes, starting with conceptualising and
drafting the ANSI X9.31 signature scheme. Using Test-Driven Development, I developed and refined
this implementation, leveraging the modular code structure from the earlier PKCS scheme.

A significant part of the week involved troubleshooting and resolving issues related to signature
verification. In the ANSI implementation, legitimate signatures occasionally failed to verify. The
problem was traced to the message encoding method and was fixed by adjusting the first padding byte.

When implementing the ISO/IEC 9796-2 scheme, I encountered a similar issue with signature
verification failures. This time, it was due to the first padding byte causing the encoded message's
big integer representation to sometimes exceed the modulus size, leading to verification failures.
After thorough research and comparison with open-source implementations, I realised the necessity of
prepending an initial 0x00 byte to the encoded message array, a Java-specific implementation detail.

The week concluded with a substantial refactoring of the ISO scheme's class structure, simplifying
it to a single class that automatically adjusts the recovery mode based on the user's message
length.

## Diary Entry - Week of 20th November - 26th November 2023

This week, I made substantial progress in both my report and the development of the proof of concept
program. I sent a draft of my report to my supervisor and rescheduled our meeting to Friday for
feedback. I then focused on developing models for the proof of concept program, beginning with the
key generation model and applying the state design pattern effectively. By midweek, I completed all
essential models for the program, setting the stage for controller development.

I then moved on to developing the program's views, ensuring they supported the observer design
pattern, and completed the implementation of all application views. After receiving positive
feedback and suggestions for minor improvements on my report from my supervisor, I advanced to
developing the controllers, completing the GenController and initiating the SignatureController.

Over the weekend, I finished the SignatureController, integrating it seamlessly with the views, and
developed the MainController to manage the application flow. The application was functionally
complete, albeit pending more rigorous testing. I concluded the week by reorganizing the project and
code directory to better reflect the MVC pattern and separate different functional modules.

## Diary Entry - Week of 27th November - 3rd December 2023

This week, I focused on finalising my project for the interim submission I started with integration
testing for the mainMenu and Sign view features using TestFX, ensuring the UI and
model-view-controller interactions worked correctly. By Tuesday, I had completed all integration
testing, including tests for the verify view, and updated the appendix with detailed test cases.

Midweek, I shifted to preparing my project presentation, developing introductory slides and key
concept overviews. During this period, I also enhanced the JavaDoc documentation across the project
and detailed the system testing results in the appendix.

On Friday, I create a new launch class for the application and generated a fat jar containing the
full application (with all classes and dependencies needed to run it). Additionally, I started
recording demo videos for the presentation and the final project submission.

Over the weekend, I put the finishing touches on the presentation slides and the demo videos. I also
updated the project's README with detailed run instructions and refined the report to incorporate
specifics from my implementation of the signature schemes.

Next, I will organise everything in a manner appropriate for the final submission and clean up any
remaining loose ends, ensuring that all elements of the project are polished.

## Diary Entry - Week of 15th January - 21st January 2024

This week was centred around preparing for the development of the more comprehensive Term 2
benchmarking program. I started with a supervisor meeting, receiving positive feedback on my interim
submission and noting that I could simplify the directory structure of my codebase, specific
requirements for the benchmarking program. My focus then shifted to researching and conceptualising
the implementation of MGF1 (Mask Generation Function 1) to meet the requirements in instantiating
the signatures with provably secure parameters for a large hash output. I updated the requirements
section of my report, redefining it for the more comprehensive benchmarking program and revising
user stories to encompass its expanded functionality. The week culminated in drafting a new UML use
case diagram and beginning to overhaul the design section to align with these new requirements.
Looking ahead, I plan to update other design diagrams and start adapting the lower level
implementation of the signature schemes for instantiation provably secure parameters.

## Diary Entry - Week of 22nd January - 28th January 2024

This week, I focused on enhancing the key generation process and refining the signature schemes in
my project. I implemented the Mask Generation Function 1 (MGF1) and modified the key generation to
support provably secure parameters, particularly enabling a smaller 'e' value. I then refactored the
hash function integration within the signature schemes, adding support for SHA-512 and improving the
design for future extensibility and updated the RSASSA_PKCS1_v1_5 scheme to allow instantiation with
these new parameters. By the end of the week, all signature schemes were adapted to be instantiated
with provably secure parameters. Additionally, I restructured the SignatureController. The refactor
involved creating a new interface for common view update operations and dividing the controller into
an abstract parent class for shared functionalities and distinct child classes for specific tasks in
signature creation and verification. This reorganisation aimed to enhance functionality and
maintenance, delineating shared and specific tasks for signature creation and verification.

## Diary Entry - Week of 29th January - 4th February 2024

This week started with a productive meeting on Monday with my supervisor, where we discussed using
two or three primes for benchmarking and implementing provably secure parameters. I also received
guidance on integrating the MGF1 function. I then adjusted the MGF1 function within signature
schemes and got approval to use a third-party library for Keccak hashing.

On Tuesday and Wednesday, I focused on integrating benchmarking features into the key generation
module, adding a toggle switch for benchmarking mode and a user interface for inputting key
generation parameters.

By Thursday, I had created a benchmarking utility class to manage timing and computation of
statistical averages, along with a loading bar for visual progress representation.

On Friday, I designed a benchmarking results screen with tabulated layout and options for textual
and visual representation, and improved efficiency through multi-core processing.

Over the weekend, I structured the development and publication of benchmarking changes,
incorporating them into the genModel, and finalising the BenchmarkingUtility class. Sunday was
dedicated to integrating these changes into the view assembly for key generation and finalsing
updates to the genModel.

## Diary Entry - Week of 5th February - 11th February 2024

This week, my efforts concentrated on integrating benchmarking functionalities across the project,
focusing on both key generation and signature modules. I started by implementing a
createBenchmarkingTask method in the key generation controller for background processing and
observing user input for initiating benchmarking tasks. This was followed by resolving timing errors
due to concurrent task overlaps and refining the public/private key batch export process.

Midweek, I enhanced memory efficiency in key generation benchmarking using replacing futures with
CountDownLatch (to track the completion of all tasks within a trial) and began developing a results
module to calculate and display statistical metrics from benchmarking activities. In the signature
module, I integrated benchmarking features for signature creation, involving a parallelised method
for batch-signing messages and revamping the UI for batch operations. I also incorporated observer
methods in the Signature Creation controller for handling batch files.

By Friday, I had implemented a structured results module, designed to handle benchmarking results
effectively. This included a ResultsModel for calculating statistical metrics, a view for displaying
results, and a controller linking benchmarking activities to the results view through a
BenchmarkingContext helper class that is extended by each benchmarking activity (e.g., class
SignatureCreationContext extends BenchmarkingContext) and passed at point of construction to the
results controller, to enable it to display tailored options on the results view.

The week concluded with a focus on the signature verification module, implementing a parallelised
batch verification method and updating the UI to support batch operations. I set plans to conduct
integration tests, refine software design specifications for the application's transition to a
benchmarking focus, and alter the signing and verifying processes to allow user-selected hash
functions.

## Diary Entry - Week of 12th February - 18th February 2024

I started with a supervisor meeting which led to a pivotal shift in my benchmarking approach,
transitioning from batch-based to individual key-based results. This change led me to rework the
batch methods in my application for accurate individual task timing and to reorganize the signature
collection process for correct verification. I also gained clarity on using hash IDs with the MGF1
function in different signature schemes, particularly in adapting the ANSI standard (the ANSI
standard is outdated and does not specify how to handle hash ID when applying the MGF1 to fixed hash
function).

Later on in the week I worked on enabling the choice of different hash functions in the signature
schemes (switching from an initial the hash map of hash IDs to storing hash IDs and static final
fields for efficiency) and adjusting the signature model to track hash types and sizes. This
required updates to the signing and verification interfaces, allowing users to select hash
functions, and modifying the Signature Controller to handle these changes.

A challenge arose with discrepancies in timing due to parallel processing. To resolve this, I
switched to sequential batch methods, ensuring precise timing. The week ended with me adapting the
results controller for managing per-key results and refactoring the signature schemes with a new
getHashID method for more efficient operations (as alluded to previously). I also added a consistent
footer across all application screens to unify the user interface.

## Diary Entry - Week of 19th February - 25th February 2024

This week, my project saw substantial enhancements in both functionality and user interface. I
introduced a toggle switch across the application screens to switch between standard and
benchmarking modes, offering users more flexibility. To address the challenges with concurrent
execution in benchmarking, I reverted to synchronous methods for key generation, signature creation,
and verification.

A significant development was the initiation of a cross-parameter comparison benchmarking mode. This
involved upgrading the ResultsView for displaying results for multiple parameter types/keys in one
table for comparison and extensively refactoring the ResultsController for this new mode, along with
integrating support into the GenController.

In the latter part of the week, I focused on finalising the cross-parameter benchmarking
implementation. This required adapting the Key generation controller to preload keys pre-load keys
into signature related controllers if the generated key batches/individual key pairs are all
provably secure or keys were generated using cross parameters comparison mode. I then refactored the
signature controller assembly to support this new mode. Functionalities for resetting preloaded key
parameters and exporting verification results for cross-parameter benchmarking were also developed.

Additionally, I enhanced the non benchmarking mode for key generation so that user is presented with
an option on whether to use a small e in the generation of key and then refined the
SignatureController to include functionality for preloading a single key for non benchmarking mode
if key chosen is provably secure i.e., small was used to generate it.

Over the weekend, I concentrated on resolving errors and bugs emerging from the integration of the
new benchmarking mode, such as fixing crashes in signature views. I also dedicated time to
refactoring, streamlining the initialisation process for the different modes to enhance the
application's efficiency and user experience.

## Diary Entry - Week of 26th February – 3rd March 2024

I started by updating the results view to include multiple graph representations, such as
histograms, box plots, and line graphs, tailored especially for comparing mean times in different
result sets. This update required substantial enhancements to the data processing backend, which I
completed successfully.

The integration of the fully-functional results graph feature into the main branch marked a
significant milestone. Building on this, I initiated the development of the
customCrossParameterBenchmarkingMode, a feature allowing users to specify precise key/parameter
configurations for benchmarking in comparison mode. This involved modifying the GenModel to handle
user-defined configurations and introducing new methods for generating readable string formats for
these custom configurations. Additionally, I implemented a toggle switch in the key generation view
and introduced dialog interactions for user input of configurations as multiple comma separated fractions.

Further refining the Signature model, I enabled the setting of a generalised number of key
configurations per key size for use in batch generation methods for comparison mode. I also enhanced
the ResultsController to dynamically construct an aggregated results table in comparison mode,
introducing a parameterised list for context-specific row headers based on previous benchmarking
tasks.

The latter part of the week saw me wrapping up the refactoring of the SignView and VerifyView domain
objects by creating a unified SignatureBaseView class. This significantly reduced code duplication
and streamlined handling across different signature views. I then conceptualised a new feature:
Multi-Hash Function Selection for Cross-Parameter Benchmarking, focusing on the specification and
management of custom key configurations.

By the weekend, I had developed a preliminary implementation of this feature, though it required
further refinement due to some bugs. By Sunday, I had completed significant enhancements across the
project to fully incorporate the Multi-Hash Function Selection feature, enabling the specification
and management of custom key configurations and grouping them to be used with selected hash
functions.

## Diary Entry - Week of 4th March – 10th March 2024

This week, I focused on refining various aspects of my project, from bug fixes to significant
restructuring. Starting with resolving an issue in GenView and a benchmarking display error on
Monday, I then introduced the ability to specify custom hash output sizes for variable-length hash
functions in comparison mode on Tuesday. This involved notable changes across the application,
including a major refactoring of the KeyConfigurationsDialog from a lengthy method in GenView into a
more manageable KeyConfigurationsDialog class.

Midweek, I refined the SignatureModel to handle custom hash outputs uniformly across different key
sizes and addressed several issues, including missing results overlay in standard mode and absence
of hash function names in benchmarking results. I also updated the export functionality to include
hash function details in signature operations.

In a shift to refactoring, I restructured the SignatureModel for unified key batch management,
reorganised the results module with new inheritance relationships (created a Graph Manager class to
delegate graph responsibility). The refactoring continued into the signature module, focusing on
streamlining digital signature operations and separating benchmarking responsibilities into new,
specialised classes e.g., involved optimising the signature model to concentrate solely on digital
signature operations and offloading benchmarking responsibilities to newly created, specialised
classes e.g., introducing AbstractSignatureModelBenchmarking as a base class for benchmarking
functions, creating SignatureModelBenchmarking and SignatureModelComparisonBenchmarking as
subclasses

The week concluded with addressing key preloading issues in standard benchmarking mode and a major
overhaul of the key generation model and results controllers. This included dividing the GenModel
class into three distinct classes: GenModel, GenModelBenchmarking, and
GenModelComparisonBenchmarking, with GenModel serving as the foundational class for RSA key
generation. In parallel, I segmented the ResultsController into ResultsBaseController,
ResultsControllerComparisonBenchmarking, and ResultsControllerNormalBenchmarking, each catering to
different benchmarking scenarios.

## Diary Entry - Week of 11th March – 17th March 2024

Early Week:
On Monday, I resolved minor issues, such as fixing the key size retrieval for verification results export in comparison
mode and updating the export functionality to include the signature scheme name. I also added images and descriptions of
the application's comparison benchmarking flow into the report.

Midweek:
Tuesday involved implementing logic to adjust hash function parameters, specifically for SHA-512 with 1024-bit keys in
standard parameter sets, to align with provably secure parameters. I decided to use the Oxford 3000 message batch for
benchmarking the signature schemes and ran a comprehensive session involving 3847 trials across six key sizes. I
encountered challenges with the ISO scheme during the verification phase due to issues in handling non-recoverable
message batches, which I planned to address the next day.

Later in the Week:
By Wednesday, I had updated the signature benchmarking model to resolve errors in verifying signatures for the ISO/IEC
9796-2 Scheme 1 and fixed various related issues. Thursday saw me completing a full benchmarking session with the ISO
scheme and capturing a complete set of results, which I began incorporating into a new results section in the report.

Weekend Focus:
On Friday and Saturday, I added screenshots of benchmarking results to the report, requiring some editing for format
suitability. I also wrote summarised descriptions and discussions under the results tables for key generation and
signature creation benchmarking for the PKCS and ANSI schemes.

Week’s End:
Sunday was dedicated to developing the results section further, adding summaries and discussions for the ISO Scheme's
signature creation benchmarking and starting on the signature verification across all schemes. By day’s end, I had
completed the PKCS signature scheme verification summary, with plans to polish it and add descriptions for the remaining
schemes.

## Diary Entry - Week of 18th March – 24th March 2024

On Monday, I focused on addressing minor details such as correcting the key size retrieval for verification
results export and updating the benchmarking results export function to include the signature scheme name. I also
ensured the functionality of exporting non-recoverable message batches in the ISO scheme during benchmarking mode.
Further, I added images and detailed explanations of the application’s comparison benchmarking flow to the report.

Tuesday was marked by implementing adjustments in hash function parameters, particularly when using SHA-512 with
1024-bit keys, to align with provably secure parameters. I chose the Oxford 3000 dataset for benchmarking the signature
schemes and ran a comprehensive session across six key sizes for key generation. Despite successfully capturing results
for the PKCS and ANSI schemes, I encountered challenges with the ISO scheme during verification, which I aimed to
address subsequently.

On Wednesday, I updated the signature benchmarking model, adding specialised methods for verifying signatures and
exporting verification results, particularly for the ISO/IEC 9796-2 Scheme 1. This resolved the issues I faced with the
ISO scheme verification. However, the day was also spent troubleshooting various errors related to variable length hash
functions and verification accuracy in the ISO scheme.

By Thursday, I had completed a full benchmarking session with the ISO scheme, capturing all relevant results and graphs.
I began incorporating these findings into the project report, adding sections on hardware specifications and the
methodology used for benchmarking.

On Friday, I integrated screenshots of the key generation benchmarking results into the report, followed by results from
benchmarking signature creation and verification for the three signature schemes. Editing these images for clarity in
the report was also part of the day’s work.

Over the weekend, I focused on writing detailed descriptions and discussions for the benchmarking results. On Saturday,
this included the key generation and signature creation benchmarking for the PKCS and ANSI schemes. On Sunday, my
efforts were directed at summarising and discussing the signature creation benchmarking results for the ISO Scheme, and
I started on the descriptions for signature verification across all schemes, completing a preliminary summary for the
PKCS scheme.

## Diary Entry - Week of 25th March – 1st April 2024

On Monday, I finished summarising and describing the benchmarking results for the ANSI and ISO schemes. Recognising the
similar patterns in signature verification results across schemes, I refined the sections to build upon one another. In
an effort to streamline the report, I moved the result tables and their descriptions for these schemes
to the appendix. I concluded the say by sending the latest draft of the report, albeit without the conclusion and
professional issues sections, to my supervisor for their input.

Later in the week, I turned my attention to implementing integration tests for each of the core application modules,
including key generation, signing, and verifying. Utilising the TestFX framework, I completed the integration test code
for key generation and published these changes to the Git repository by Friday's end. I also initiated coding for
integration  tests of the signature module and its associated MVC components.

By the end of the week, on Sunday, I had successfully completed the integration tests for the signature module. This
included finalising tests for both signature creation and verification, and updating the project repository accordingly.
Alongside this, I began the process of documenting systems test cases that I had previously conducted. Starting with the
key generation systems tests, I added these descriptions to the corresponding section in the report’s appendix.