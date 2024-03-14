import hashlib
from typing import List
from base_crack import PasswordCracker
from crack_settings import *

import multiprocessing as mp
from datetime import datetime
from ctypes import c_wchar_p

def num_to_base(n, b):
    """Converts an integer to a list of integers, where each element represents a digit in the base given."""
    if n == 0: return [0]
    digits = []
    while n > 0:
        digits.append(n % b)
        n //= b
    return list(reversed(digits))

class MultiCPUPasswordCracker(PasswordCracker):
    
    def __init__(self, cores: int, max_len: int = 4, charset: list = LOWERCASE_LETTERS + UPPERCASE_LETTERS, starting_pw='', encoding='utf-8'):
        super().__init__("Multi-core Password Cracker", encoding)
        self.cores = cores
        self.max_len = max_len
        self.charset = charset
        self._starting_pw = starting_pw
        
        

    def _find_password(self, target_hash: str) -> None:
        
        # Divide up the search space based on the number of cores
        total_num = len(self.charset)**self.max_len
        num_per_core = total_num // self.cores
        current_pw_num = 0
        last_pw_num = current_pw_num + num_per_core
        print(total_num, num_per_core)
        
        # Thread-safe data storage
        manager = mp.Manager()
        pw_value = manager.Value(c_wchar_p, " "*self.max_len)

        # Early stopping
        found_event = mp.Event()

        # Begin a process for each core
        process_list = []
        for i in range(self.cores):
            current_pw_str = self._intlist_to_str(num_to_base(current_pw_num, len(self.charset)))
            # last_pw_str = self._intlist_to_str(num_to_base(last_pw_num, len(self.charset))) \
            #                 if i < self.cores - 1 else self.charset[-1] * self.max_len
            
            p = mp.Process(target=self._find_password_range_mp, args=(target_hash, current_pw_str, num_per_core, pw_value, found_event))
            process_list.append(p)

            current_pw_num += num_per_core + 1
            # last_pw_num += num_per_core + 1

            # In case of small search space
            if current_pw_num > total_num:
                break
        for p in process_list:
            p.start()
        for p in process_list:
            p.join()

        if pw_value.value != " "*self.max_len:
            crack_attempt = self._crack_attempts[target_hash]
            crack_attempt.cracked = True
            crack_attempt.end_time = datetime.now()
            crack_attempt.password = pw_value.value

    def _find_password_range_mp(self, target_hash: str, starting_pw: str, num_pws: int, pw_value, found_event):
        
        current_pw_str = bytearray(starting_pw, self._encoding)
        current_pw_intlist = [self.charset.find(x) for x in starting_pw]
        
        # Special case: checking password of length zero
        if len(current_pw_intlist) == 0:
            current_pw_intlist = [0]
        
        pws_checked = 0
        while True:
            # Check if the current password matches the target hash
            if self._compare_md5_hash(target_hash, current_pw_str):
                pw_value.value = current_pw_str.decode(self._encoding)
                print(f"T({starting_pw}:{num_pws}): Found the password! {pw_value.value}")
                found_event.set()
                return
            # End if another process has found the password
            if found_event.is_set():
                print(f"T({starting_pw}:{num_pws}): Terminating.")
                return
            # End if last password in range
            if (pws_checked >= num_pws) or (len(current_pw_intlist) > self.max_len):
                print(f"T({starting_pw}:{num_pws}): Search space checked, no pw found.")
                return
            # Increment password (ex.  'aabc' -> 'aabd' or 'AZZZ' -> 'Baaa')
            pws_checked += 1
            current_pw_intlist[-1] += 1
            if current_pw_intlist[-1] >= len(self.charset):
                i = len(current_pw_intlist) - 1
                # Increment previous characters as necessary

                while i > 0 and current_pw_intlist[i] >= len(self.charset):
                    current_pw_intlist[i] = 0
                    current_pw_str[i] = ord(self.charset[0])
                    current_pw_intlist[i-1] += 1
                    i -= 1
                # Special case: all passwords tried for this length
                if current_pw_intlist[0] >= len(self.charset):
                    current_pw_intlist = [0] * (len(current_pw_intlist) + 1) # array of zeros of length n+1
                    current_pw_str = bytearray(self.charset[0] * len(current_pw_intlist), self._encoding)
                else:
                    current_pw_str[i] = ord(self.charset[current_pw_intlist[i]])
            else:
                current_pw_str[-1] = ord(self.charset[current_pw_intlist[-1]])

     ### Useful MD5 hashing helper functions
    def _compare_md5_hash(self, target_hash: str, str_to_hash: str) -> str:
        """Checks if a given password matches an MD5 hash."""
        return self._md5_hash(str_to_hash).upper() == target_hash.upper()

    def _md5_hash(self, str_to_hash: str) -> str:
        """Return the MD5 hexdigest hash for a string."""
        return hashlib.md5(str_to_hash, usedforsecurity=False).hexdigest()

    ## Other helper
    def _intlist_to_str(self, int_list: List[int]) -> str:
        """Converts a list of ints with indexes in the charset to a string"""
        return "".join([self.charset[x] for x in int_list])
    