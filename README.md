<h1> AIG Shields Up Cybersecurity Job Simulation</h1>
<h2>Objective:</h2>
<br>You are an Information Security Analyst in the Cyber & Information Security Team.
A common task and responsibility of information security analysts is to stay on top of emerging vulnerabilities to make sure that the company can remediate them before an attacker can exploit them. 
In this task, you will be asked to review some recent publications from the Cybersecurity & Infrastructure Security Agency (CISA).</br>

<br>The Cybersecurity & Infrastructure Security Agency (CISA) is an Agency that has the goal of reducing the nation’s exposure to cybersecurity threats and risks. 
After reviewing the publications, you will then need to draft an email to inform the relevant infrastructure owner at AIG of the seriousness of the vulnerability that has been reported. 
</br>
<h2>Task 1: </h2>
<br> Respond to the Apache Log4j zero-day vulnerability that was released to the public by advising affected teams of the vulnerability.</br> 

<h3>Below is the email I created to advise the affected teams. </h3>

<br>From: AIG Cyber & Information Security Team
To: <affected team>
Subject: Security Advisory concerning  a critical vulnerability has surfaced

Hello John Doe,

AIG Cyber & Information Security Team would like to inform you that a recent Apache Log4j software vulnerability has been discovered in the security community that may affect Product Development Staging Environment infrastructure.

Vulnerability Overview:

Log4j is a widely-used open-source tool for application logging and monitoring on the web. Recently, a critical vulnerability has surfaced in versions Log4j2 2.0-beta9 through 2.15.0. 
This flaw enables an unauthorized attacker to execute remote code on affected systems, posing a significant threat. For more details, refer to the NIST disclosures: NVD - CVE-2021-44228 and NVD - CVE-2021-45046.

Affected Products:
Log4j2 2.0-beta9 through 2.15.0

Risk & Impact:
This vulnerability is classified as critical, allowing remote code execution (RCE). Attackers can exploit it to infiltrate the Product Development Staging Environment infrastructure, potentially compromising data or executing malicious activities.

Remediation:
Identify any assets or infrastructure running the vulnerable Log4j version.
Upgrade to the following secure versions: Log4j 2.16.0 (Java 8) and 2.12.2 (Java 7).
Stay vigilant for any indications of exploitation.

If you detect any signs of exploitation, please report them immediately. Once you've addressed this vulnerability, kindly confirm with the security team by responding to this email.
For any questions or issues, don’t hesitate to reach out to us.

Kind regards,

AIG Cyber & Information Security Team </br>

<h2>Task 2 : </h2>
<br> I wrote a Python script to brute force the decryption key of the encrypted file, to avoid paying a ransom. </br>

<h2>Objective for Task 2:  </h2>

<br>  Your advisory email in the last task was great. It provided context to the affected teams on what the vulnerability was, and how to remediate it. 
Unfortunately, an attacker was able to exploit the vulnerability on the affected server and began installing a ransomware virus. 

Luckily, the Incident Detection & Response team was able to prevent the ransomware virus from completely installing, so it only managed to encrypt one zip file. 

Internally, the Chief Information Security Officer does not want to pay the ransom, because there isn’t any guarantee that the decryption key will be provided or that the attackers won’t strike again in the future. 

Instead, we would like you to brute force the decryption key. Based on the attacker’s sloppiness, we don’t expect this to be a complicated encryption key, because they used copy-pasted payloads and immediately tried to use ransomware instead of moving around laterally on the network.

Here is a sample Python script to brute force the decryption key of the encrypted file. </br> 

<br> from zipfile import ZipFile
def attempt_extract(zf_handle, password):
    try:
        zf_handle.extractall(pwd=password)
        return True
    except:
        return False

def main():
    print("[+] Beginning bruteforce ")
    with ZipFile('enc.zip') as zf:
        with open('rockyou.txt', 'rb') as f:
            for p in f:
                password = p.strip()
                if attempt_extract(zf, password):
                    print("[+] Correct password: %s" % password)
                    exit(0)
                else:
                    print("[-] Incorrect password: %s" % password)

    print("[+] Password not found in list")

if __name__ == "__main__":
    main() </br>


 
 
 
 
 
 

 



