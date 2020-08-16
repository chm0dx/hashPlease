#!/usr/bin/env python3

import argparse
import random
import hashlib
import crypt
import string
from Crypto.Cipher import DES

parser = argparse.ArgumentParser(description="Generate hashes for different algs using wordlists and masks.")
parser.add_argument('--showDetails', dest='deets', help='Wanna see the plaintext, mask/wordlist, and alg?', action='store_true')
parser.add_argument('--wordList', dest='wordList', help='Provide a custom wordlist to select passwords from.', action='store', default='./wordlists/sampleWords')
parser.add_argument('--maskList', dest='maskList', help='Provide a custom list of masks to generate passwords from.', action='store', default='./masks/KoreLogic_PathWell')
args = parser.parse_args()
deets = args.deets
wordList = args.wordList
maskList = args.maskList

def MaskToPassword(mask):

	if(deets):
		print("Mask:\t\t" + mask)
	# Strip the question marks
	mask = mask[1::2]
	password = ""

	# Translate the mask to eligible characters.
	for c in mask:
		if c == "u":
			password += random.choices(string.ascii_uppercase,k=1)[0]
		elif c == "l":
			password += random.choices(string.ascii_lowercase,k=1)[0]
		elif c == "d":
			password += random.choices(string.digits,k=1)[0]
		elif c == "s":
			password += random.choices(string.printable[62:95],k=1)[0]
		elif c == "a":
			password += random.choices(string.printable[0:95],k=1)[0]
		elif c == "h":
			password += random.choices(string.hexdigits.lower(),k=1)[0]
		elif c == "H":
			password += random.choices(string.hexdigits,k=1)[0]
	
	return password

def SevenBitPlusParity(chunk):
	# For each chunk, concat bytes before 7-bit split and parity
	
	combined = ""
	for i in range(0,len(chunk)):
		combined += bin(chunk[i])[2:].zfill(8)

	grouped = []
	parity = []

	for i in range(0,56,7):
		grouped.append(combined[i:i+7])

	# Parity = if odd # of bits set, add 0 as lowest bit
	# if even # of bits set, add 1 as lowest bit
	for group in grouped:
		if grouped.count("1") % 2 == 0:
			parity.append(bin((int(group,2) * 2) + 1)[2:].zfill(8))
		else:
			parity.append(bin(int(group,2) * 2)[2:].zfill(8))
		
	return parity

def lmGen(plain):

	# Convert to upper
	upperPlain = plain.upper().encode("ISO-8859-1").decode()

		# Split into two 7-char chunks
	
	chunks = []
	constant = "KGS!@#$%"
	hsh = ""

	for i in range(0,14,7):
		chunk = []
		for c in upperPlain[i:i+7]:
			chunk.append(ord(c))
		chunks.append(chunk)

	# Pad to 7 chars if needed
	for i in range(0,2):
		pad = 7 - len(chunks[i])
		for ii in range(0,pad):
				chunks[i].append(0)
		key = b''
		for ii in SevenBitPlusParity(chunks[i]):
			key = key + bytes([int(ii,2)])
		
		cipher = DES.new(key, DES.MODE_ECB)
		msg = cipher.encrypt(constant)
		for ii in msg:
			hsh = hsh + format(ii,'02x')
			
	return hsh

selectionMethods = ["wordlist", "mask"]

# Randomly select wordlist or mask as means to generate password.
if random.choices(selectionMethods)[0] == "mask":
	if(deets):
		print("Mode:\t\tmask " + "(" + maskList + ")")
	word = MaskToPassword(random.choices(list(open(maskList)))[0].rstrip())

else:
	if(deets):	
		print("Mode:\t\twordlist " + "(" + wordList + ")")
	word = random.choices(list(open(wordList)))[0].rstrip()
	
if(deets):
	print("Password:\t" + word)

hashFormats = [ "md5crypt","sha256crypt","sha512crypt","lm","ntlm" ]
hashFormat = random.choices(hashFormats)[0]

# Don't want lm for passwords longer than 14 chars.
while hashFormat == "lm":
	if len(word) > 14:
			hashFormat = random.choice(hashFormats)
	else:
			break

if(deets):
	print("Hash Alg:\t" + hashFormat)

# Randomly select a hash alg.
hsh = ""
if hashFormat == "md5crypt":
	hsh = crypt.crypt(word, '$1$' + ''.join(random.choices(string.ascii_letters + string.digits,k=8)))
elif hashFormat == "sha256crypt":
	hsh = crypt.crypt(word, '$5$' + ''.join(random.choices(string.ascii_letters + string.digits,k=8)))
elif hashFormat == "sha512crypt":
	hsh = crypt.crypt(word, '$6$' + ''.join(random.choices(string.ascii_letters + string.digits,k=8)))
elif hashFormat == "lm":
	hsh = lmGen(word).upper()
elif hashFormat == "ntlm":
	hsh = hashlib.new('md4', (word).encode('utf-16le')).hexdigest().upper()

print("Hash:\t\t" + hsh)
