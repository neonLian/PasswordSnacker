import hashlib
from collections import deque
from typing import List 

from base_crack import PasswordCracker
from crack_settings import *

class SimplePasswordCracker(PasswordCracker):
    def __init__(self, max_len: int = 4, charset: list = LOWERCASE_LETTERS + UPPERCASE_LETTERS, starting_pw='', encoding='utf-8'):
        super().__init__("Single-core Password Cracker", encoding)
        self.max_len = max_len
        self.charset = charset
        self._starting_pw = starting_pw

    def _find_password(self, target_hash: str) -> None:
        # Convert string of characters to list of numbers (so the numbers can be incremented easily)
        # Each number is an index for the charset string
        self._find_password_range(target_hash, self._starting_pw, self.charset[-1]*self.max_len)

    def _find_password_range(self, target_hash: str, starting_pw: str, ending_pw: str):
        current_pw_intlist = [self.charset.find(x) for x in starting_pw]
        ending_pw_intlist = [self.charset.find(x) for x in ending_pw]
        
        while len(current_pw_intlist) <= self.max_len:
            # Check if the current password matches the target hash
            if self._compare_md5_hash(target_hash, self._intlist_to_str(current_pw_intlist)):
                self._save_cracked_password(target_hash, self._intlist_to_str(current_pw_intlist))
                return
            # Special case: checking password of length zero
            if len(current_pw_intlist) == 0:
                current_pw_intlist = [0]
                continue
            # Special case: last password in range
            if (current_pw_intlist == ending_pw_intlist):
                return
            # Increment password (ex.  'aabc' -> 'aabd' or 'AZZZ' -> 'Baaa')
            current_pw_intlist[-1] += 1
            if current_pw_intlist[-1] >= len(self.charset):
                i = len(current_pw_intlist) - 1
                # Increment previous characters as necessary
                while i > 0 and current_pw_intlist[i] >= len(self.charset):
                    current_pw_intlist[i] = 0
                    current_pw_intlist[i-1] += 1
                    i -= 1
                # Special case: all passwords tried for this length
                if current_pw_intlist[0] >= len(self.charset):
                    current_pw_intlist = [0] * (len(current_pw_intlist) + 1) # array of zeros of length n+1
            

    def _intlist_to_str(self, int_list: List[int]) -> str:
        """Converts a list of ints with indexes in the charset to a string"""
        return "".join([self.charset[x] for x in int_list])

    def _find_password_qb(self, target_hash: str) -> None:
        """Alternative queue based method, high memory consumption"""
        __pw_queue = deque()
        __pw_queue.append("")
        
        while len(__pw_queue) > 0:
            current_pw = __pw_queue.popleft()
            # Check if the current password matches the target hash
            if self._compare_md5_hash(target_hash, current_pw):
                self._save_cracked_password(target_hash, current_pw)
                return
            # End the search if the maximum permitted length to check for has been reached
            if len(current_pw) >= self.max_len:
                continue  
            # Try adding every possible character on to the current password
            for a in self.charset:
                # Add next password to try to the end of the queue
                __pw_queue.append(current_pw + a)
    
    
	