import re
class SSHUser():
    def __init__(self, username, last_logdate):
        self.username = username
        self.last_logdate = last_logdate
    def validate(self):
        pattern=re.compile(r'^[a-z_][a-z0-9_-]{0,31}$')
        if re.match(pattern, self.username) is None:
            return False
        return True