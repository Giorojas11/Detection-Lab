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

#### Network

![image](https://github.com/Giorojas11/Detection-Lab/assets/98496056/7f86e731-524e-419f-8b8f-f3c13a8e0007)

*Ref 1: Network Diagram*

### SERVER SETUP 

#### SPLUNK SERVER (Ubuntu)

1. Installed and configured Linux (Ubuntu) 22.04 on a VirtualBox VM.
2. Ran *sudo nano /etc/netplan/TAB* and *sudo netplan apply* to assign a static IP address, the google DNS, and a default route for internet access.
3. Confirmed network configuration via *ip a* and tested network connectivity via *ping 8.8.8.8*.

![image](https://github.com/Giorojas11/Detection-Lab/assets/98496056/53b5c9fc-496c-40f6-9c1e-df991c66b559)

4. Created a shared folder directory for Splunk Enterprise using the Shared Folder feature on Virtualbox. 
5. I installed virtualbox add-ons (virtualbox-guest-additions-iso and virtualbox-guest-utils) via *sudo apt-get install* commands. I added my user account to the group with the shared folder.
6. I then created a directory to use called 'Share' using the *mkdir share* command. I mounted the shared folder from my host to the Share directory.

![image](https://github.com/Giorojas11/Detection-Lab/assets/98496056/c8557e4e-110c-4494-86f3-069675290287)

8. Ran the Splunk installer from the Share directory, changed to > changed to Splunk user > *cd /bin* and ran the Splunk license agreement and installer
9.  Confirmed Splunk server was reachable from Target-PC using 192.168.10.10:8000

#### TARGET-PC (Windows 10)
1. Installed Splunk Universal Forwarder and Sysmon with sysmonconfig.xml from https://github.com/olafhartong/sysmon-modular
2. Set up Splunk Universal Forwarder to connect Target-PC to Splunk Server.
3. Ran Sysmon installtion with the sysconfig.xml file from Powershell
4. Created an inputs.conf file with the following stanzas:
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
*NOTE: This file tells Splunk Forwarder what information will be pushed to the Splunk server. In this case, Event Viewer (Application, Security, and System) and Sysmon information will be sent to an Index titled "endpoint"*

4. Services > Splunk Forwarder > Restarted service
   *NOTE: Splunk Forwarder needs to be restarted after every inputs.conf change made*
6. Created an 'enpoint' index in Splunk so info can be received, added a receiving port of 9997, added the Target-PC to the index, and confirmed information is being sent from Target-PC to the Splunk server.

#### AD/DC SERVER
1. Repeated Steps 1-4 from TARGET-PC.
2. Confirmed traffic is flowing from AD server to Splunk server.
3. Server Manager > Manage > Installed and configured Active Directory Domain Services.
4. Created Domain
5. Created 3 OUs to mimic different departments within the company, and added user accounts to each OU.
6. Added TARGET-PC to Domain.

### THE ATTACK

*The Scenario*: The attacker was able to tailgate into SOC's office site and proceed by doing some reconnaissance. An active ethernet port was found allowing the attacker to connect to the office network. John Smith, a new IT employee for SOC, has RDP privileges for their job-role. Being a new employee, John was given a simple password that needed to be manually changed as soon as possible.

1. On my Kali Linux VM, I installed Crowbar, a brute force tool.
2. I created a soc_project directory on the desktop, pulled the rockyou.txt and copied it to the directory as a new file, passwords.txt. I added the password that is used by John Smith's useer account in the SOC domain. In this attack scenario, the attacker did reconnaissance and was able to gain John Smith's password.
3. I ran the following command and was able to get successfully get John's username and password.
   
![image](https://github.com/Giorojas11/Detection-Lab/assets/98496056/9eb600ee-3272-4c06-a94a-93a249f89c2e)

4. I went to Splunk to review the telemetry generated from this attack. Events were generated for failed login attempts by John Smith under Event Code 4625 sourced from Event Viewer: Security. The 20+ login attempts in a minute would warrant an investigation since it probably indicates a brute force attack. If the Cyber Incident Response Cycle were followed, isolating the user account and device would be next.

![image](https://github.com/Giorojas11/Detection-Lab/assets/98496056/045c196d-e4bd-411e-850d-60c1fa5df823)

Upon reviewing Event Code 4624, the network information lists the Kali VM and its IPv4 address.

![image](https://github.com/Giorojas11/Detection-Lab/assets/98496056/3cb5a8e1-db42-483f-9fb6-bd9129bd44e3)

### ATOMIC RED TEAM

1. I installed AtomicRedTeam on TARGET-PC via Powershell:
   
![image](https://github.com/Giorojas11/Detection-Lab/assets/98496056/7815a2da-61ba-4a33-ba6f-6cd48893a39a)

AtomicRedTeam runs tactics, techniques, & procedures (TTPs) from the MITRE ATT&CK framework from a device's Powershell and are logged in Splunk for review.  I went to https://attack.mitre.org/ and selected a few to test.

1a. Create Account - Local Account -T1136.001 

![image](https://github.com/Giorojas11/Detection-Lab/assets/98496056/5cf15f71-03af-41ec-bcd5-aa116dc988e9)

1b. Command and Scripting Interpreter - Powershell - T1059.001

![image](https://github.com/Giorojas11/Detection-Lab/assets/98496056/55922047-18b0-494c-af45-fe7caa94dab8)
![image](https://github.com/Giorojas11/Detection-Lab/assets/98496056/20ab8949-dcbf-4409-b017-9a2bef2eab92)
![image](https://github.com/Giorojas11/Detection-Lab/assets/98496056/d688bc5d-354f-46bc-ae2c-2213243814ed)
![image](https://github.com/Giorojas11/Detection-Lab/assets/98496056/d9ab21ad-7080-4a80-8aef-5869003bb484)
![image](https://github.com/Giorojas11/Detection-Lab/assets/98496056/73aff2d4-e2f1-48cf-baa5-7fc6ec7c47a2)
![image](https://github.com/Giorojas11/Detection-Lab/assets/98496056/4a9cfed6-3aaf-455c-8aad-8914bbf9b82a)

This script was also being picked up by Windows Security in real-time.

![image](https://github.com/Giorojas11/Detection-Lab/assets/98496056/5baeb3e4-cf6b-4631-a634-97b49071acc3)

2. I then reviewed the AtomicRedTeam generated telemetry in Splunk:

2a. From Create Account - Local Account -T1136.001 

![image](https://github.com/Giorojas11/Detection-Lab/assets/98496056/4f80bd3a-915a-49a8-8241-818f0a2f9e0f)

2b. From Command and Scripting Interpreter - Powershell - T1059.001

![image](https://github.com/Giorojas11/Detection-Lab/assets/98496056/2c0978bc-66b0-4b9c-b552-ac97cc294d76)

## Conclusion
With this virtual environment, I can practice Red Team (attack simulation) while simultaneously practicing Blue Team (log analysis on SIEM). My plan is to expand this homelab and continue simulating attacks and playing around with the SIEM to practice to gain hand-on experience in prepration for a SOC Analyst role.
