import datetime
import re
import ipaddress
from abc import ABC, abstractmethod
class SSHLogEntry(ABC):
    def __init__(self, log):
        try:
            self.raw_desc=log
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
    def __str__(self):
        return f'{self.month} {self.day} {self.time} {self.username} {self.pid} {self.description}'
    
    def get_ipv4s(self):
        ipv4_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        ipv4_addresses = re.findall(ipv4_pattern, self.description)
        if len(ipv4_addresses) == 0:
            return None
        ipv_list = []
        for ip in ipv4_addresses:
            if ip not in ipv_list:
                ipv_list.append(ipaddress.IPv4Address(ip))
        return ipv_list
    import re
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
    @property
    def has_ip(self):
        return self.get_ipv4s() is not None
    def __repr__(self) -> str:
        return super().__repr__()
    def __eq__(self, o: object) -> bool:
        return super().__eq__(o)
    def __gt__(self, o: object) -> bool:
        return super().__gt__(o)
    def __lt__(self, o: object) -> bool:
        return super().__lt__(o)
    


class SSH_error(SSHLogEntry):
    def __init__(self, log):
        super().__init__(log)
        self.error = self.description
        self.messege= self.get_messege_type()
    def __str__(self):
        return f'{'\033[93m'}{self.month} {self.day} {self.time} {self.username} {self.pid} {self.description} {self.error}{'\033[0m'}'
    def validate(self):                   
        if 'error' in self.raw_desc.lower():
            return True
        return False

class SSH_accepted(SSHLogEntry):
    def __init__(self, log):
        super().__init__(log)
        self.accepted = self.description
        self.messege= self.get_messege_type()
    def __str__(self):
        return f'{'\033[92m'}{self.month} {self.day} {self.time} {self.username} {self.pid} {self.description} {self.accepted}{'\033[0m'}'
    def validate(self):
        if 'accepted' in self.raw_desc.lower():
            return True
        return False

class SSH_rejected(SSHLogEntry):
    def __init__(self, log):
        super().__init__(log)
        self.rejected = self.description
        self.messege= self.get_messege_type()
    def __str__(self):
        return f'{'\033[91m'}{self.month} {self.day} {self.time} {self.username} {self.pid} {self.description} {self.rejected}{'\033[0m'}'
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
SSH=SSH_rejected('Dec 10 07:07:38 LabSZ sshd[24206]: input_userauth_request: invalid user test9 [preauth]')
print(SSH.__str__())