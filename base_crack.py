import hashlib
from typing import Dict, Optional
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta

"""Stores password and time information about a crack attempt."""
@dataclass
class CrackInfo:
    start_time: datetime
    end_time: datetime = None
    cracked: bool = False
    password: str = None

    def time_taken(self) -> timedelta:
        """Returns time taken to crack password"""
        if not self.cracked:
            raise ValueError("Password not cracked yet")
        return self.end_time - self.start_time
    
    def time_taken_str(self) -> str:
        """Returns time taken string with most appropriate units"""
        td = self.time_taken()
        if td < timedelta(milliseconds = 1): return f"{td.microseconds:d} μs"
        if td < timedelta(seconds=1): return f"{td.microseconds//1000:d} ms"
        if td < timedelta(minutes=1): return f"{td.total_seconds():2.2f} s"
        return f"{int(td.total_seconds() // 3600):d} h {int((td.total_seconds() % 3600) // 60):d} m {(td.total_seconds() % 3600) % 60:.2f} s"
        
    
    def __str__(self):
        return self.password if self.cracked else "<Unknown password>"

class PasswordCracker(ABC):
    """PasswordCracker is an abstract class containing common methods for cracking MD5 hashes and returning the results."""

    def __init__(self, name="Generic Password Cracker", encoding='utf-8'):
        self._crack_attempts = {}
        self.name = name
        self._encoding = encoding

    def get_passwords(self) -> Dict[str, CrackInfo]:
        """Returns a dict where the keys are hashes and values are information for successfully cracked passwords."""
        return {k: v for k, v in self._crack_attempts.items() if v.cracked}
    
    def get_attempts(self) -> Dict[str, CrackInfo]:
        """Returns a dict where the keys are hashes and values are information for all password cracking attempts."""
        return self._crack_attempts
    
    def get_attempt(self, pw_hash) -> Optional[CrackInfo]:
        return self._crack_attempts[pw_hash] if pw_hash in self._crack_attempts else None

    def _save_cracked_password(self, target_hash: str, cracked_pw: str):
        """Save the cracked password for a given hash."""
        crack_attempt = self._crack_attempts[target_hash]
        crack_attempt.cracked = True
        crack_attempt.end_time = datetime.now()
        crack_attempt.password = cracked_pw
    
    def crack_hash(self, target_hash: str) -> None:
        """Find the password corresponding to a given hash."""
        self._crack_attempts[target_hash] = CrackInfo(start_time = datetime.now())
        self._find_password(target_hash)        

    @abstractmethod
    def _find_password(self, target_hash: str) -> None:
        """Search for the password that matches with the given hash"""
        pass

    ### Useful MD5 hashing helper functions
    def _compare_md5_hash(self, target_hash: str, str_to_hash: str) -> str:
        """Checks if a given password matches an MD5 hash."""
        return self._md5_hash(str_to_hash).upper() == target_hash.upper()

    def _md5_hash(self, str_to_hash: str) -> str:
        """Return the MD5 hexdigest hash for a string."""
        return hashlib.md5(str_to_hash.encode(self._encoding), usedforsecurity=False).hexdigest()