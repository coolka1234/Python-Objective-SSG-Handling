import SSHLogEntry, SSHLogJournal, SSHUser
import datetime
import re
with open('SSH_log_test.log', 'r') as file:
    logs = file.readlines()
    journal = SSHLogJournal.SSHLogJournal()
    for log in logs:
        journal.append(log)
    filtered_entries=SSHLogJournal.SSHLogJournal.filter(journal, month='Dec')
    SSHUser1 = SSHUser.SSHUser('____lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll', 'Dec  1 00:00:00')
    SSHUser2 = SSHUser.SSHUser('user2', 'Dec  1 00:00:00')
    SSHUser3 = SSHUser.SSHUser('', 'Dec  1 00:00:00')
    filtered_entries.append(SSHUser1)
    filtered_entries.append(SSHUser2)
    filtered_entries.append(SSHUser3)
    for entry in filtered_entries:
        print(entry.validate())
