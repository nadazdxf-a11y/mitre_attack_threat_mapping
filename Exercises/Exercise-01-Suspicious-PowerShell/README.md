# Exercise 01 — Suspicious PowerShell Activity

## Scenario Summary
A SOC analyst investigated a compromised Windows workstation after an employee opened a suspicious email attachment.

The investigation revealed that:

- The user opened a malicious Microsoft Word document received through email.
- `WINWORD.EXE` launched `powershell.exe`.
- PowerShell executed a command that downloaded a file from an external server.
- The downloaded file was executed on the workstation.

- ## Observed Behaviors

Before mapping the incident to MITRE ATT&CK, the observed behaviors were extracted from the scenario:

1. A malicious Microsoft Word document was received through email and opened.
2. `WINWORD.EXE` launched `powershell.exe`.
3. PowerShell downloaded a file from an external server.
4. The downloaded file was executed on the workstation.


## MITRE ATT&CK Mapping

### Behavior 1 — Malicious Email Attachment

**Observed behavior:**  
The user opened a malicious Microsoft Word document received through email.

**Tactic:**  
Initial Access — `TA0001`

**Technique:**  
Phishing: Spearphishing Attachment — `T1566.001`

**Reasoning:**  
The attacker used a malicious file delivered through email to gain access to the victim's environment. The behavior matches the use of a malicious attachment as an initial access mechanism.


 ### Behavior 2 — Word Launches PowerShell

**Observed behavior:**  
`WINWORD.EXE` launched `powershell.exe`.

**Tactic:**  
Execution — `TA0002`

**Technique:**  
Command and Scripting Interpreter: PowerShell — `T1059.001`

**Reasoning:**  
The evidence shows that Microsoft Word launched PowerShell, which was used to execute commands on the workstation. This behavior maps to the PowerShell sub-technique under Command and Scripting Interpreter.


### Behavior 3 — File Download

**Observed behavior:**  
PowerShell downloaded a file from an external server.

**Tactic:**  
Command and Control — `TA0011`

**Technique:**  
Ingress Tool Transfer — `T1105`

**Reasoning:**  
The scenario explicitly states that a file was transferred from an external server to the compromised workstation. This behavior is consistent with Ingress Tool Transfer, which describes transferring tools or files into a compromised environment.


### Behavior 4 — Downloaded File Execution

**Observed behavior:**  
The downloaded file was executed on the workstation.

**Tactic:**  
Execution — `TA0002`

**Technique:**  
Undetermined

**Reasoning:**  
The scenario confirms that the downloaded file was executed, but it does not provide enough information about how the file was executed. Therefore, a specific MITRE ATT&CK technique cannot be confidently assigned.

Additional evidence such as process creation logs, parent-child process relationships, command-line arguments, file type, or user interaction would be required to determine the specific execution technique.


## Mapping Summary

| # | Observed Behavior | Tactic | Technique | ID |
|---|---|---|---|---|
| 1 | Malicious Word attachment opened | Initial Access | Spearphishing Attachment | T1566.001 |
| 2 | Word launched PowerShell | Execution | PowerShell | T1059.001 |
| 3 | File downloaded from external server | Command and Control | Ingress Tool Transfer | T1105 |
| 4 | Downloaded file executed | Execution | Undetermined | — |
## Evidence-Based Reasoning

The MITRE ATT&CK mappings in this exercise were based only on behaviors explicitly described in the scenario.

No technique was assigned when the available evidence was insufficient to determine the exact execution method.

This approach helps avoid unsupported assumptions and keeps the analysis evidence-based.

## Key Takeaways

- Extract the observed behavior before selecting a MITRE ATT&CK technique.
- Identify the tactic based on the attacker's objective or action.
- Select the technique that best describes the observed behavior.
- Do not assume a technique when the scenario does not provide enough evidence.
- Parent-child process relationships can provide valuable evidence during SOC investigations.
- MITRE ATT&CK mapping should describe what the attacker actually did, not what they could potentially have done.
