# hashdump-reporter
Python utility for parsing secretsdump.py output, written in Python3

## Description
`hashdump-reporter.py` was written to help penetration testers with testing and reporting for weak and reused passwords. I wrote this specifically to help my team and I with our password management findings, so the formatted output is tailored to our findings.<p>
`hashdump-reporter.py` aims to solve the following challenges in testing and reporting:
- Parsing NT hashes from either SAM or NTDS for cracking
- Ingesting output potfiles from hashcat/hashtopolis to identify accounts with weak passwords
- Identifying accounts with reused passwords
- Identifying hosts reusing passwords for local accounts
- Generating *meaningful* output on the above points that clients can easily digest and implement remediation for.
<p>

Generating that *meaningful* output can be a big challenge when reporting on credentials, particularly in large Active Directory environments. As long as passwords are being used, some users will inevitably use weak passwords. Additionally, administrators all too often will either use a single account for domain administration that is shared (frequently with a bad password) or will reuse the password for their low-privilege account with their admin account. In large environments, this can result in findings that are hundreds or thousands of lines long simply listing these accounts. When clients scroll through a penetration test report and see these ridiculous tables, they'll frequently skip over the finding altogether. To assist clients in implementing proper password controls, `hashdump-reporter.py` generates various output files to provide easily digestible data that clients can act on.

## Installation
This tool requires the `pandas` Python package.
```
pip install pandas
./hashdump-report.py -h
```

## Usage
```
usage: hashdump-reporter.py [-h] [-i inputFile | -d inputDir] [-o outputFile] [-l adminsFile] [-p hc.txt] [-admin] [-user] [-computer] [-history] [-x] [-pass-len MinPassLen]

Secretsdump Report Generator

options:
  -h, --help                           show this help message and exit
  -i inputFile, --ntds inputFile       input NTDS/SAM file
  -d inputDir, --dir inputDir          directory of SAM files to parse
  -o outputFile, --outfile outputFile  prepend output file name
  -l adminsFile, --users adminsFile    text file of privileged users
  -p hc.txt, --potfile hc.txt          hashcat/john potfile containing <hash>:<plaintext
  -admin                               parse admin reuse
  -user                                parse all domain reuse
  -computer                            Include computer hashes in <out>.uniqhashes. Does not affect TSVs
  -history                             include NTDS password history in parsed NTDS TSV. Does not affect uniqhashes
  -x, --excel                          generate excel formulas for tracking document
  -pass-len MinPassLen                 AD Minimum Password Length Policy setting. Only used for excel formulas
```

## Administrators
The `-l <adminsFile>` option takes a plaintext file of users, one per line, with administrative privileges in the domain. How you determine "administrative" privileges is up to you.<p>
If you can gain a shell on a domain controller, such as through WinRM/PSRemoting, I recommend the following PowerShell commands to get a list of privileged group members. The list of groups comes from Microsoft documentation:
```PowerShell
$admingroups = @("Administrators","Domain Admins","Enterprise Admins","Schema Admins","Account Operators","Backup Operators","Enterprise Key Admins","Group Policy Creator Owners", "Cert Publishers", "DnsAdmins")
$adminusers = @()
foreach ($group in $admingroups) { $adminusers += get-adgroupmember -rec $group }
($adminusers | sort -property samaccountname -unique).samaccountname
```
[Privileged Accounts and Groups in Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory)



## Output formats
`hashdump-reporter.py` will generate output files, in TSV format, based on user supplied arguments for the following:
### Parsed NTDS/SAM
`-i <NTDS/SAM>`

| Account | RID | LM Hash | NT Hash |
| --- | --- | --- | --- |
| CONTOSO\Administrator | 500 | aad3b435b51404eeaad3b435b51404ee | 8846f7eaee8fb117ad06bdd830b7586c |
| CONTOSO\JohnDoe | 1000 | aad3b435b51404eeaad3b435b51404ee | 8846f7eaee8fb117ad06bdd830b7586c |

### Password Reuse
#### Local
`-d <inputDir>`

| IP Address | Hostname | Account | Password Hash |
| --- | --- | --- | --- |
| 10.10.10.10 | HOST1 | Administrator | 8846f7eaee8fb117ad06bdd830b7586c |
| 10.10.10.20 | HOST2 | LocalAdmin | 8846f7eaee8fb117ad06bdd830b7586c |

#### Domain
Output format 1, to list all accounts with reused passwords:<p>
`-user`
`secretsdump-parsed-pw-reuse-all.tsv`

| Account | Password Hash |
| --- | --- |
| CONTOSO\Administrator | 8846f7eaee8fb117ad06bdd830b7586c |
| CONTOSO\JohnDoe | 8846f7eaee8fb117ad06bdd830b7586c |

Output format 2, to list only password reuse among administrators and low-privilege accounts (`;;; ` is intended to be a unique separator for doing a find/replace operation in Excel/Word):<p>
`-admin -l adminsFile`
`secretsdump-parsed-pw-reuse-admin.tsv`

| Admin Accounts | User Accounts | Password Hash |
| --- | --- | --- |
| CONTOSO\Administrator;;; CONTOSO\WebAdmin;;; CONTOSO\ServerAdmin | CONTOSO\JohnDoe;;; CONTOSO\PlainJane | 8846f7eaee8fb117ad06bdd830b7586c |

### Weak Passwords
Requires `-p <potFile>`. The output format is the same for parsing all accounts and just administrator accounts (requires `-l adminsFile`).
`secretsdump-parsed-weak-pw-[all|admin].tsv`

| Account | \<blank\> | Account |
| --- | --- | --- |
| CONTOSO\Administrator | \<blank\> | CONTOSO\JohnDoe |
| CONTOSO\PlainJane | \<blank\> | [N/A] |

## Excel Formulas
`hashdump-reporter.py` can also output helper forumlas for use in the parsed TSV in Excel (or other spreadsheet applications that support the same formulas).<p>
The formulas are intended to be used with two tabs in Microsoft Excel, where Tab1 is `hashes` and Tab2 is `cracked`, with `cracked` having the output of the cracked password TSV. `cracked` would need to be expanded with a fourth column containing the "method" or wordlist used in hashcat/hashtopolis for Column G to work properly. Column P in `hashes` should have the list of administrators in the domain (samaccountname, not UPN or down-level logon name)
The formulas would be placed into Row 2 of the `hashes` tab and produce output like the following once dragged down to the end of the spreadsheet:

| A | B | C | D | E | F | G | H | I | J | K | L | M | N | O | P |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Account | RID | LM Hash | NT Hash | Reuse | Cracked | Method | Plaintext | Password Length | isBelowMin | isAdmin | | Cracked: 86% | | | Administrators |
| CONTOSO\Administrator | 500 | aad3b435b51404eeaad3b435b51404ee | 8846f7eaee8fb117ad06bdd830b7586c | 3 | YES | Rockyou | password | 8 | - | YES | | | | | WebAdmin |
| CONTOSO\JohnDoe | 1000 | aad3b435b51404eeaad3b435b51404ee | 8846f7eaee8fb117ad06bdd830b7586c | 3 | YES | Rockyou | password | 8 | - | - | | | | | ServerAdmin |
| CONTOSO\PlainJane | 1001 | aad3b435b51404eeaad3b435b51404ee | 8846f7eaee8fb117ad06bdd830b7586c | 3 | YES | Rockyou | password | 8 | - | - | | | |
| CONTOSO\WebAdmin | 1002 | aad3b435b51404eeaad3b435b51404ee | 36aa83bdcab3c9fdaf321ca42a31c3fc | 2 | YES | Rockyou | pass | 4 | YES | YES | | | |
| CONTOSO\ServerAdmin | 1003 | aad3b435b51404eeaad3b435b51404ee | 36aa83bdcab3c9fdaf321ca42a31c3fc | 2 | YES | Rockyou | pass | 4 | YES | YES | | | |
| CONTOSO\Justin | 1004 | aad3b435b51404eeaad3b435b51404ee | 6c9678ef8cf497ef2ea6c91a9f7ecf2a | 1 | - | - | - | - | - | - | | | |
| CONTOSO\Jake | 1005 | aad3b435b51404eeaad3b435b51404ee | 31d6cfe0d16ae931b73c59d7e0c089c0 | 1 | YES | Blank | N/A [Blank] | - | - | - | | | |





