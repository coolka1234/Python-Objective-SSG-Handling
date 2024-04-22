import datetime
import re
import ipaddress
from abc import ABC, abstractmethod
import datetime
class SSHLogEntry(ABC):
    def __init__(self, log):
        try:
            self._raw_desc=log
            log= log.split(': ')
            data_list = log[0].split()
            self.month = data_list[0]
            self.day = data_list[1]
            self.time = data_list[2]
            self.username = data_list[3]
            self.pid = data_list[4]
            if(len(log)>2):
                self.description = log[1] + log[2]
            else:
                self.description = log[1]
        except Exception:
            self.description = "incorrect log format"
    
    raw_desc=property(
        lambda self: self._raw_desc,
        lambda self, value: setattr(self, '_raw_desc', value),
        lambda self: delattr(self, '_raw_desc'),
        doc='raw description of the log entry'
    )

    def __str__(self):
        return f'{self.month} {self.day} {self.time} {self.username} {self.pid} {self.description}'
    
    def get_ipv4s(self):
        ipv4_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        ipv4_addresses = re.match(ipv4_pattern, self.description)
        if len(ipv4_addresses) == 0:
            return None
        return [ipaddress.ip_address(ip) for ip in ipv4_addresses]
    
    
    def get_messege_type(self):
        success_pattern = r'check pass'
        fail_pattern = r'authentication failure|authentication failures'
        disconnect_pattern = r'disconnect|Connection closed'
        failed_password_pattern = r'Failed password|failed password'
        invalid_user_pattern = r'invalid user|Invalid user'
        break_in_attempt_pattern = r'POSSIBLE BREAK-IN ATTEMPT!'
        if re.search(success_pattern, self.description):
            return 'success_login'
        elif re.search(fail_pattern, self.description):
            return 'failed_login'
        elif re.search(disconnect_pattern, self.description):
            return 'disconnect'
        elif re.search(failed_password_pattern, self.description):
            return 'failed password'
        elif re.search(invalid_user_pattern, self.description):
            return 'invalid user'
        elif re.search(break_in_attempt_pattern, self.description):
            return 'break in attempt'
        else:
            return 'other'
    @abstractmethod
    def validate(self):
        pass
    has_ip = property(get_ipv4s)
    @property
    def has_ip(self):
        return self.get_ipv4s() is not None
    def __repr__(self) -> str:
        return f"SSHLogEntry({self.month}, {self.day}, {self.time}, {self.username}, {self.pid}, {self.description})"
    def __eq__(self, o: object) -> bool:
        if self.month == o.month and self.day == o.day and self.time == o.time and self.username == o.username and self.pid == o.pid and self.description == o.description:
            return True
        return False
    def __gt__(self, o: object) -> bool:
        if datetime.datetime.strptime(self.month+self.day+self.time, '%b%d%H:%M:%S') > datetime.datetime.strptime(o.month+o.day+o.time, '%b%d%H:%M:%S'):
            return True
        return False
    def __lt__(self, o: object) -> bool:
        if datetime.datetime.strptime(self.month+self.day+self.time, '%b%d%H:%M:%S') < datetime.datetime.strptime(o.month+o.day+o.time, '%b%d%H:%M:%S'):
            return True
        return False
    


class SSH_error(SSHLogEntry):
    def __init__(self, log):
        super().__init__(log)
        self.error_desc = re.findall(r'error:.*', self.description)
        self.messege= self.get_messege_type()
    def __str__(self):
        return f'{'\033[93m'}{self.month} {self.day} {self.time} {self.username} {self.pid} {self.description} {self.error_desc}{'\033[0m'}'
    def validate(self):                   
        if 'error' in self.raw_desc.lower():
            return True
        return False

class SSH_accepted(SSHLogEntry):
    def __init__(self, log):
        super().__init__(log)
        self.user = re.findall(r'for \w+', self.description)
        self.port = re.findall(r'port \d+', self.description)
        self.messege= self.get_messege_type()
    def __str__(self):
        return f'{'\033[92m'}{self.month} {self.day} {self.time} {self.username} {self.pid} {self.description} {self.user}{'\033[0m'}'
    def validate(self):
        if 'accepted' in self.raw_desc.lower():
            return True
        return False

class SSH_rejected(SSHLogEntry):
    def __init__(self, log):
        super().__init__(log)
        self.user = re.findall(r'user \w+', self.description)
        self.port = re.findall(r'port \d+', self.description)
        self.messege= self.get_messege_type()
    def __str__(self):
        return f'{'\033[91m'}{self.month} {self.day} {self.time} {self.username} {self.pid} {self.description} {self.user}{'\033[0m'}'
    def validate(self):
        if 'failed' in self.raw_desc.lower():
            return True
        return False

class SSH_other(SSHLogEntry):
    def __init__(self, log):
        super().__init__(log)
        self.other = self.description
        self.messege= self.get_messege_type()
    def __str__(self):
        return f'{'\033[94m'}{self.month} {self.day} {self.time} {self.username} {self.pid} {self.description} {self.other}{'\033[0m'}'
    def validate(self):
        return True
#test
SSH=SSH_other('Dec 10 07:07:38 LabSZ sshd[24206]: input_userauth_request: invalid user test9 [preauth]')
print(SSH.__str__())