import SSHLogEntry
class SSHLogJournal:
    def __init__(self):
        self.entries = []

    def append(self, entry):
        newEntry= SSHLogEntry.SSH_error(entry)
        newEntry.validate()
        self.entries.append(newEntry)
    
    def __len__(self):
        return len(self.entries)

    def __iter__(self):
        self.current_index = 0
        return self
    def __contains__(self, entry):
        return entry in self.entries

    def __next__(self):
        if self.current_index >= len(self.entries):
            raise StopIteration
        entry = self.entries[self.current_index]
        self.current_index += 1
        return entry
    
    def filter(self, **kwargs):
        filtered_entries = []
        for entry in self.entries:
            if all([getattr(entry, key) == value for key, value in kwargs.items()]):
                filtered_entries.append(entry)
        return filtered_entries