# SPL Queries - Privilege Escalation Detection

## Detection Query
index=windows_security (EventCode=4720 OR EventCode=4732 OR EventCode=4728)

## Detailed Table View
index=windows_security (EventCode=4720 OR EventCode=4732)
| table _time, EventCode, Member_Account_Name, Group_Name
| sort -_time