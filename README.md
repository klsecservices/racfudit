**Description**

Racfudit is a tool for analyzing Resource Access Control Facility (RACF) database which contains security information of z/OS users, groups, datasets and other system entities. That information includes access rights, password hashes, certificates, group memberships, and more. The tool allows you to extract this information from the RACF database and present it in one of two forms: a dumped flat plain text file or a sqlite3 database where you can query the required security information and detect misconfigurations and weak points in the target z/OS system.

The tool has been tested on z/OS version V1R13 and V2R02.

**Usage**
```
racfudit -f racfdb -dump racfdb.txt 
racfudit -f racfdb -dump racfdb.txt -sql racfdb.db
racfudit -f racfdb -sql racfdb.db -log racfudit.log
```
