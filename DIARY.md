#Diary
## Diary Entry: Week of 18th - 24th September 2023

This week was dedicated to writing a first draft of the abstract for my project PKCS#1 v1.5 digital signature scheme for my project and researching arbitrary precision arithmetic for I library I may look to implement as part of the aims for the project

On Monday, I started writing about its importance, touching on its widespread use and history. Tuesday was a continuation, emphasising why it's such a vital system.

By Wednesday, I added details on potential security issues, particularly focusing on something called the Bleichenbaucher attacks. I was initially puzzled about how these attacks affected the signature scheme.

On Thursday and Friday, after more research, I figured out the difference between how these attacks affect encryption and signature aspects of the system. This helped clarify some of my earlier confusion.

Over the weekend, I added insights on why, despite some concerns, many still prefer the PKCS system. I also touched upon a new research finding that supports its use. By Sunday, I detailed my main goals for this project, hoping to create a useful tool that compares different signature schemes.

Next I will clarify whether I should consider implementing a self-made big number library as part of the project and hopefully advance significantly in the creation of the project plan.


## Diary Entry - Week of 25th September - 1st October 2023

Met with my supervisor for initial meeting. Discussed potential extensions to the original project specifications and in general what the project entails. Refocused and refined the project plan, emphasising deterministic RSA hash-and-sign schemes, especially PKCS#1 v1.5. Made structural changes to the introduction and abstract, enhancing clarity. Set up the Maven project directory on GitLab and further developed the project timeline. Transitioned all documentation from Microsoft Word to latex, drafting the literature review in the process. By week's end, automated referencing in latex for enhanced efficiency.

## Diary Entry - Week of 2nd October - 8th October 2023

This week, I refined and expanded the Risks and mitigation section, established a risk quantification table, and deepened my understanding of digital signature schemes. The literature review for the interim report was integrated, and significant progress was made in drafting the cryptographic foundation of the report. By the weekend, focus was channeled into classifying digital signature schemes and laying out a clear structure for detailed exploration of specific signature schemes in upcoming sessions. Next I will begin writing the introductory section on digital signatures for my report.

## Diary Entry - Week of 9th October - 15th October 2023

I Started the week with supervisor meeting, confirming my focus on the POC PKCS Signature for term 1 and was given advise to potentially using the top 1000 English words for the signature program when I sought guidance on the type of data I could provide to be signed. I delved into textbook RSA, highlighting its vulnerabilities. By Friday, I had expanded on RSA's role in digital signatures, introducing potential attacks and Hashed RSA signatures. The weekend saw me laying the foundation for all three schemes considered in the project by formally defining them. I then began to explore the motivation of provably secure signature schemes.

 
## Diary Entry - Week of 16th October - 22nd October 2023
I started the week attempting to try and understanding trapdoor permutations, especially how they tie into RSA. Following this I began work on enumerating the requirements for the proof of concept program. By the end Friday, I had detailed the user stories and actors for the program with a corresponding a UML use case diagram. During the weekend I first focussed on expanding the motivation for provable security section with subsections on real world implications and limitations. I finished off the week on Sunday by trimming down the report to make it more concise.

## Diary Entry - Week of 23rd October - 29th October 2023

The week started with a meeting where I received constructive feedback on my project plan, specifically that I had spent too much time on PKCS#1 v1.5 encryption scheme and Bleichenbacher attacks, which were deemed beyond the project’s scope. We clarified the implications of the interim report's word limit, and I was reassured that my report’s structure was on the right track, though I was advised against including full software design documents.

I primarily focused on refining my project plan based on feedback. After restructuring my report and creating an appendix for the software requirements of the proof of concept program, I turned my attention to conceptualising and beginning the implementation of the RSA key generation process, culminating in a complete first draft by Friday. The weekend was dedicated to initiating a new chapter on security proof in the report, laying down the foundational concepts and starting to weave them into the project's larger narrative.

