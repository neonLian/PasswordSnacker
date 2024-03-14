import argparse, os

from base_crack import PasswordCracker, CrackInfo
from simple_crack import SimplePasswordCracker
from multicpu_crack import MultiCPUPasswordCracker
from gpu_crack import GPUPasswordCracker
from crack_settings import *

def choose_cracker(args: argparse.Namespace) -> PasswordCracker:

    charset = ""
    if 'a' in args.charset: charset += LOWERCASE_LETTERS
    if 'A' in args.charset: charset += UPPERCASE_LETTERS
    if '1' in args.charset: charset += NUMBERS
    if 's' in args.charset: charset += SPECIALS1 + SPECIALS2

    if args.cores > 1:
        return MultiCPUPasswordCracker(cores=args.cores, encoding=args.file_encoding, max_len=int(args.max_length), charset=charset)
    else:
        return SimplePasswordCracker(encoding=args.file_encoding, max_len=int(args.max_length), charset=charset)

def print_crack_attempt(hash: str, info: CrackInfo):
    if info.cracked:
        print(hash, info.password, info.time_taken_str(), sep="\t")
    else:
        print(hash, info, sep="\t")

def main():
    # Read in command line arguments
    parser = argparse.ArgumentParser(prog="main.py", description="Brute-forces an MD5 password hash.")

    parser.add_argument('hash_file')
    parser.add_argument('-m', '--max-length', default=4, type=int, help="Maximum length password to try")
    parser.add_argument('-c', '--charset', default='aA1', help="Character flags to include (a = lower, A = upper, 1 = number, s = special)")
    parser.add_argument('-s', '--start-at', default="", help="The password to try first (passwords will be checked in alphabetic order)")
    parser.add_argument('-n', '--cores', default=1, type=int, help="If using CPU, number of cores to use.")
    parser.add_argument('-g', '--gpu', default=False, action='store_true', help="Use the GPU to crack the password.")
    parser.add_argument('-e', '--file-encoding', default='utf-8', help='The encoding of the hashes file.')

    args = parser.parse_args()

    # Choose single core, multicore, or GPU based cracker
    cracker = choose_cracker(args)
    print("Running " + cracker.name)

    # Loop through every line in the hashes file and begin cracking
    with open(args.hash_file, 'r') as f:
        for line in f.readlines():
            hash = line.strip()
            print("Cracking: " + hash)
            cracker.crack_hash(hash)
            print_crack_attempt(hash, cracker.get_attempt(hash))
    
    # Print the output
    print("\n", "=" * (os.get_terminal_size().columns-5))
    crack_dict = cracker.get_attempts()
    for k, v in crack_dict.items():
        print_crack_attempt(k, v)
        

if __name__ == '__main__':
    main()