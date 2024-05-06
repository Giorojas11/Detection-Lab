# Detection Lab

## Objective

The Detection Lab project aimed to establish a controlled environment for simulating and detecting cyber attacks. The primary focus was to ingest and analyze logs within a Security Information and Event Management (SIEM) system, generating test telemetry to mimic real-world attack scenarios. This hands-on experience was designed to deepen understanding of different types of attacks, attack detection, and SIEM Log Analysis.

### Skills Learned

- Advanced understanding of SIEM concepts and practical application.
- Proficiency in analyzing and interpreting SIEM logs.
- Ability to conduct attacks on server and client endpoints.
- Ability to generate and recognize attack signatures and patterns.
- Enhanced knowledge of security vulnerabilities.
- Enhanced knowledge of active directory management.
- Development of critical thinking and problem-solving skills in cybersecurity.

### Tools Used

- Security Information and Event Management (SIEM) system for log ingestion and analysis.
- Active Directory for domain network management.
- Kali Linux system for attack simulation.
- Telemetry generation tools to create realistic network traffic and attack scenarios.

## Steps

*Ref 1: Network Diagram*

![image](https://github.com/Giorojas11/SOC_Lab/assets/98496056/0ec0ba49-1c72-4e1c-af57-137d9adbe2bb)

#### SPLUNK SERVER (Ubuntu)
1. Added host directory containing Splunk Enterprise via Hypervisor > created a shared directory between Host and VM
2. Ran Splunk from Share directory > changed to Splunk user > Ran Splunk license agreement and installer from Bin
3. Set server to run Splunk on boot with user "Splunk"
4. Confirmed Splunk server was reachable from Target-PC using Splunk Server's IP:8000

#### TARGET-PC (Windows 10)
1. Installed Splunk Universal Forwarder and Sysmon with an Olaf sysmonconfig file from Github
2. Ran Sysmon with config file from Powershell
3. Created an inputs.conf file:
-------------------------------
[WinEventLog://Application]

index = endpoint

disabled = false

[WinEventLog://Security]

index = endpoint

disabled = false

[WinEventLog://System]

index = endpoint

disabled = false

[WinEventLog://Microsoft-Windows-Sysmon/Operational]

index = endpoint

disabled = false

renderXml = true

source = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

--------------------------------
NOTE: This file tells Splunk Forwarder what information will be pushed to the Splunk server. In this case, Event Viewer (Application, Security, and System) and Sysmon information will be sent to an Index titled "endpoint"

4. Services > Splunk Forwarder > Restarted service (NOTE: Splunk Forwarder needs to be restarted after every inputs.conf change made).
5. Created an enpoint index in Splunk so info can be received, added a receiving port of 9997, confirmed information is being sent from Target-PC to the Splunk server.

#### AD SERVER
1. Repeated Steps 1-4 from TARGET-PC
2. Confirmed traffic is flowing from AD server to Splunk server
3. Server Manager > Manage > Installed and configured Active Directory Domain Services
4. Created Domain
5. Created 3 OUs, added user accounts to each
6. Added TARGET-PC to Domain

### THE ATTACK

The scenario: The attacker was able to tailgate into SOC's office and proceed by doing some reconnaissance. An active ethernet port was found allowing the attacker to connect to the office network. John Smith, a new IT employee for SOC, has RDP privileges for their job-role. Being a new employee, John was given a simple password that needed to be manually changed as soon as possible.

1. On my Kali Linux VM, I installed Crowbar, a brute force tool
2. I created a soc_project directory on the desktop, pulled the rockyou.txt and copied it to the directory as a new file, passwords.txt. I added the password that is used by a user account, John Smith, in the SOC domain. In this attack scenario, the attacker did reconnaissance and was able to gain John Smith's password.
3. I ran the following command and was able to get successfully get John's username and password.
   
![image](https://github.com/Giorojas11/SOC_Lab/assets/98496056/730ece27-bc5a-418d-8542-0bd9443f07ad)

4. I then went to Splunk to review the telemetry generated from this incident. When reviewing Splunk logs, events were generated for failed login attempts by John Smith under Event Code 4625. The speed in which these attempts happened would warrant an investigation since it probably indicates a brute force attack is occurring. If the Cyber Incident Response Cycle were followed, isolating the user account and device would be next.

![image](https://github.com/Giorojas11/SOC_Lab/assets/98496056/e1f47408-0156-4bd1-82f8-80474f5f231f)

Upon reviewing Event Code 4624, the network information lists the Kali VM and its IPv4 address.

![image](https://github.com/Giorojas11/SOC_Lab/assets/98496056/967cb242-37aa-4c1d-af5b-7b29453e085c)

### ATOMIC RED TEAM
1. I installed AtomicRedTeam on TARGET-PC via Powershell:
![image](https://github.com/Giorojas11/Detection-Lab/assets/98496056/7815a2da-61ba-4a33-ba6f-6cd48893a39a)

AtomicRedTeam runs techniques from the MITRE ATT&CK framework in Powershell and are logged in Splunk for review.  I went to https://attack.mitre.org/ and selected a few to test.

1a. Create Account - Local Account -T1136.001 

![image](https://github.com/Giorojas11/Detection-Lab/assets/98496056/5cf15f71-03af-41ec-bcd5-aa116dc988e9)

1b. Command and Scripting Interpreter - Powershell - T1059.001

![image](https://github.com/Giorojas11/Detection-Lab/assets/98496056/55922047-18b0-494c-af45-fe7caa94dab8)
![image](https://github.com/Giorojas11/Detection-Lab/assets/98496056/20ab8949-dcbf-4409-b017-9a2bef2eab92)
![image](https://github.com/Giorojas11/Detection-Lab/assets/98496056/d688bc5d-354f-46bc-ae2c-2213243814ed)
![image](https://github.com/Giorojas11/Detection-Lab/assets/98496056/d9ab21ad-7080-4a80-8aef-5869003bb484)
![image](https://github.com/Giorojas11/Detection-Lab/assets/98496056/73aff2d4-e2f1-48cf-baa5-7fc6ec7c47a2)
![image](https://github.com/Giorojas11/Detection-Lab/assets/98496056/4a9cfed6-3aaf-455c-8aad-8914bbf9b82a)

This script was also being picked up by Windows Defender in real-time.

![image](https://github.com/Giorojas11/Detection-Lab/assets/98496056/5baeb3e4-cf6b-4631-a634-97b49071acc3)


2. I then reviewed the AtomicRedTeam generated telemetry in Splunk:

2a. From Create Account - Local Account -T1136.001 

![image](https://github.com/Giorojas11/Detection-Lab/assets/98496056/4f80bd3a-915a-49a8-8241-818f0a2f9e0f)

2b. From Command and Scripting Interpreter - Powershell - T1059.001

![image](https://github.com/Giorojas11/Detection-Lab/assets/98496056/2c0978bc-66b0-4b9c-b552-ac97cc294d76)


