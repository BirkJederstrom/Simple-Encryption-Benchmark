#This script is constructed to study and analyze the speed at which a simple password of 4-digits can be broken using simple algorithms
#This script tests unsalted hashes, a predetermined salt for a hash, and a randomly generated salt for each hash
#This script tests the following encryptions; MD5, SHA-1, SHA-256, SHA3-256, and SHA3-512.
#Argon2id is omited due to issues involving Windows 11 integration on the PC used

#This script is for educational purposes
#You may use this script for educational, analytical, and ethical hacking purposes
#You may not use this script maliciously
#The author takes no responsibility over any malicious use

#Authored by Birk Jederstrom

#Neccesary to use hashes and encryptions
import hashlib

#Argon2 imports
from argon2 import PasswordHasher

#Timer imports
import time

#Secrets imports
#IMPORTANT: Used for security reasons, to prevent easily guessed randomized values.
import secrets

#Password
pword = '9999'

#Hashes
hashedBenchmarkMD5 = hashlib.md5(pword.encode()).hexdigest()
hashedBenchmarkSHA1 = hashlib.sha1(pword.encode()).hexdigest()
hashedBenchmarkSHA256 = hashlib.sha256(pword.encode()).hexdigest()
hashedBenchmarkSHA3_256 = hashlib.sha3_256(pword.encode()).hexdigest()
hashedBenchmarkSHA3_512 = hashlib.sha3_512(pword.encode()).hexdigest()

#Identical Salt field
saltIdentical = 'qwerty'

#Salted hashes
SaltedhashedBenchmarkMD5 = hashlib.md5((pword + saltIdentical).encode()).hexdigest()
SaltedhashedBenchmarkSHA1 = hashlib.sha1((pword + saltIdentical).encode()).hexdigest()
SaltedhashedBenchmarkSHA256 = hashlib.sha256((pword + saltIdentical).encode()).hexdigest()
SaltedhashedBenchmarkSHA3_256 = hashlib.sha3_256((pword + saltIdentical).encode()).hexdigest()
SaltedhashedBenchmarkSHA3_512 = hashlib.sha3_512((pword + saltIdentical).encode()).hexdigest()

#Randomly generated salts
MD5RandomSalt = secrets.token_hex(16)
SHA1RandomSalt = secrets.token_hex(16)
SHA256RandomSalt = secrets.token_hex(16)
SHA3_256RandomSalt = secrets.token_hex(16)
Sha3_512RandomSalt = secrets.token_hex(16)

#Randomly salted hashes
RandomlySaltedhashedBenchmarkMD5 = hashlib.md5((pword + MD5RandomSalt).encode()).hexdigest()
RandomlySaltedhashedBenchmarkSHA1 = hashlib.sha1((pword + SHA1RandomSalt).encode()).hexdigest()
RandomlySaltedhashedBenchmarkSHA256 = hashlib.sha256((pword + SHA256RandomSalt).encode()).hexdigest()
RandomlySaltedhashedBenchmarkSHA3_256 = hashlib.sha3_256((pword + SHA3_256RandomSalt).encode()).hexdigest()
RandomlySaltedhashedBenchmarkSHA3_512 = hashlib.sha3_512((pword + Sha3_512RandomSalt).encode()).hexdigest()
       
#Argon2 Hash
ph = PasswordHasher()
hash_value = ph.hash('9999')

def findMD5Hash(hashedBenchmark):

    #Start timer
    start = time.time()

    #Password finding loop
    x = 0
    for x in range(10000):
        D = '{:04d}'.format(x)

        #If matching hash found inside the loop body
        #Ends immediately if found
        if hashlib.md5(D.encode()).hexdigest() == hashedBenchmark:
            end = time.time()
            length = end - start
            print("Pass found ", D)
            break

    return length

def findSHA1Hash(hashedBenchmark):

    #Start timer
    start = time.time()

    #Password finding loop
    x = 0
    for x in range(10000):
        D = '{:04d}'.format(x)

        #If matching hash found inside the loop body
        #Ends immediately if found
        if hashlib.sha1(D.encode()).hexdigest() == hashedBenchmark:
            end = time.time()
            length = end - start
            print("Pass found ", D)
            break

    return length

def findSHA256Hash(hashedBenchmark):

    #Start timer
    start = time.time()

    #Password finding loop
    x = 0
    for x in range(10000):
        D = '{:04d}'.format(x)

        #If matching hash found inside the loop body
        #Ends immediately if found
        if hashlib.sha256(D.encode()).hexdigest() == hashedBenchmark:
            end = time.time()
            length = end - start
            print("Pass found ", D)
            break

    return length

def findSHA3_256Hash(hashedBenchmark):

    #Start timer
    start = time.time()

    #Password finding loop
    x = 0
    for x in range(10000):
        D = '{:04d}'.format(x)

        #If matching hash found inside the loop body
        #Ends immediately if found
        if hashlib.sha3_256(D.encode()).hexdigest() == hashedBenchmark:
            end = time.time()
            length = end - start
            print("Pass found ", D)
            break

    return length

def findSHA3_512Hash(hashedBenchmark):

    #Start timer
    start = time.time()

    #Password finding loop
    x = 0
    for x in range(10000):
        D = '{:04d}'.format(x)

        #If matching hash found inside the loop body
        #Ends immediately if found
        if hashlib.sha3_512(D.encode()).hexdigest() == hashedBenchmark:
            end = time.time()
            length = end - start
            print("Pass found ", D)
            break

    return length

MD5Time = findMD5Hash(hashedBenchmarkMD5)
SHA1Time = findSHA1Hash(hashedBenchmarkSHA1)
SHA256Time = findSHA256Hash(hashedBenchmarkSHA256)
SHA3_256Time = findSHA3_256Hash(hashedBenchmarkSHA3_256)
SHA3_512Time = findSHA3_512Hash(hashedBenchmarkSHA3_512)

print("Results: ")
print("MD5 time: ", MD5Time, "ms")
print("Sha1 time: ", SHA1Time, "ms")
print("Sha256 time: ", SHA256Time, "ms")
print("Sha3_256 time: ", SHA3_256Time, "ms")
print("Sha3_512 time: ", SHA3_256Time, "ms")

print()
print("Argon2id ignored due to difficulties in the work environment with Python3 and Pip in Windows11")

print()
print("Checking results with indentical salt for all encryptions")
print()

def findSaltedMD5Hash(hashedBenchmark):

    #Start timer
    start = time.time()

    #Password finding loop
    x = 0
    for x in range(10000):
        D = ('{:04d}'.format(x) + saltIdentical)

        #If matching hash found inside the loop body
        #Ends immediately if found
        if hashlib.md5(D.encode()).hexdigest() == hashedBenchmark:
            end = time.time()
            length = end - start
            print("Pass + Salt found: ", D)
            password = D.replace(saltIdentical, "")
            print("The Password :", password)
            print("The salt was: ", saltIdentical)
            break

    return length

def findSaltedSHA1Hash(hashedBenchmark):

    #Start timer
    start = time.time()

    #Password finding loop
    x = 0
    for x in range(10000):
        D = ('{:04d}'.format(x) + saltIdentical)

        #If matching hash found inside the loop body
        #Ends immediately if found
        if hashlib.sha1(D.encode()).hexdigest() == hashedBenchmark:
            end = time.time()
            length = end - start
            print("Pass + Salt found: ", D)
            password = D.replace(saltIdentical, "")
            print("The Password :", password)
            print("The salt was: ", saltIdentical)
            break

    return length

def findSaltedSHA256Hash(hashedBenchmark):

    #Start timer
    start = time.time()

    #Password finding loop
    x = 0
    for x in range(10000):
        D = ('{:04d}'.format(x) + saltIdentical)

        #If matching hash found inside the loop body
        #Ends immediately if found
        if hashlib.sha256(D.encode()).hexdigest() == hashedBenchmark:
            end = time.time()
            length = end - start
            print("Pass + Salt found: ", D)
            password = D.replace(saltIdentical, "")
            print("The Password :", password)
            print("The salt was: ", saltIdentical)
            break

    return length

def findSaltedSHA3_256Hash(hashedBenchmark):

    #Start timer
    start = time.time()

    #Password finding loop
    x = 0
    for x in range(10000):
        D = ('{:04d}'.format(x) + saltIdentical)

        #If matching hash found inside the loop body
        #Ends immediately if found
        if hashlib.sha3_256(D.encode()).hexdigest() == hashedBenchmark:
            end = time.time()
            length = end - start
            print("Pass + Salt found: ", D)
            password = D.replace(saltIdentical, "")
            print("The Password :", password)
            print("The salt was: ", saltIdentical)
            break

    return length

def findSaltedSHA3_512Hash(hashedBenchmark):

    #Start timer
    start = time.time()

    #Password finding loop
    x = 0
    for x in range(10000):
        D = ('{:04d}'.format(x) + saltIdentical)

        #If matching hash found inside the loop body
        #Ends immediately if found
        if hashlib.sha3_512(D.encode()).hexdigest() == hashedBenchmark:
            end = time.time()
            length = end - start
            print("Pass + Salt found: ", D)
            password = D.replace(saltIdentical, "")
            print("The Password :", password)
            print("The salt was: ", saltIdentical)
            break

    return length

SaltedMD5Time = findSaltedMD5Hash(SaltedhashedBenchmarkMD5)
SaltedSHA1Time = findSaltedSHA1Hash(SaltedhashedBenchmarkSHA1)
SaltedSHA256Time = findSaltedSHA256Hash(SaltedhashedBenchmarkSHA256)
SaltedSHA3_256Time = findSaltedSHA3_256Hash(SaltedhashedBenchmarkSHA3_256)
SaltedSHA3_512Time = findSaltedSHA3_512Hash(SaltedhashedBenchmarkSHA3_512)
#argonTime = 0.0

print("-------- Salted --------")
print("Results: ")
print("MD5 time: ", SaltedMD5Time, "ms")
print("Sha1 time: ", SaltedSHA1Time, "ms")
print("Sha256 time: ", SaltedSHA256Time, "ms")
print("Sha3_256 time: ", SaltedSHA3_256Time, "ms")
print("Sha3_512 time: ", SaltedSHA3_256Time, "ms")

print()
print("Argon2id ignored due to difficulties in the work environment with Python3 and Pip in Windows11")

print()
print("Checking results with randomly generated salt for all encryptions")
print()

def findRandomlySaltedMD5Hash(hashedBenchmark):

    #Start timer
    start = time.time()

    #Password finding loop
    x = 0
    for x in range(10000):
        D = ('{:04d}'.format(x) + MD5RandomSalt)

        #If matching hash found inside the loop body
        #Ends immediately if found
        if hashlib.md5(D.encode()).hexdigest() == hashedBenchmark:
            end = time.time()
            length = end - start
            print("Pass + Salt found: ", D)
            password = D.replace(MD5RandomSalt, "")
            print("The Password :", password)
            print("The salt was: ", MD5RandomSalt)
            break

    return length

def findRandomlySaltedSHA1Hash(hashedBenchmark):

    #Start timer
    start = time.time()

    #Password finding loop
    x = 0
    for x in range(10000):
        D = ('{:04d}'.format(x) + SHA1RandomSalt)

        #If matching hash found inside the loop body
        #Ends immediately if found
        if hashlib.sha1(D.encode()).hexdigest() == hashedBenchmark:
            end = time.time()
            length = end - start
            print("Pass + Salt found: ", D)
            password = D.replace(SHA1RandomSalt, "")
            print("The Password :", password)
            print("The salt was: ", SHA1RandomSalt)
            break

    return length

def findRandomlySaltedSHA256Hash(hashedBenchmark):

    #Start timer
    start = time.time()

    #Password finding loop
    x = 0
    for x in range(10000):
        D = ('{:04d}'.format(x) + SHA256RandomSalt)

        #If matching hash found inside the loop body
        #Ends immediately if found
        if hashlib.sha256(D.encode()).hexdigest() == hashedBenchmark:
            end = time.time()
            length = end - start
            print("Pass + Salt found: ", D)
            password = D.replace(SHA256RandomSalt, "")
            print("The Password :", password)
            print("The salt was: ", SHA256RandomSalt)
            break

    return length

def findRandomlySaltedSHA3_256Hash(hashedBenchmark):

    #Start timer
    start = time.time()

    #Password finding loop
    x = 0
    for x in range(10000):
        D = ('{:04d}'.format(x) + SHA3_256RandomSalt)

        #If matching hash found inside the loop body
        #Ends immediately if found
        if hashlib.sha3_256(D.encode()).hexdigest() == hashedBenchmark:
            end = time.time()
            length = end - start
            print("Pass + Salt found: ", D)
            password = D.replace(SHA3_256RandomSalt, "")
            print("The Password :", password)
            print("The salt was: ", SHA3_256RandomSalt)
            break

    return length

def findRandomlySaltedSHA3_512Hash(hashedBenchmark):

    #Start timer
    start = time.time()

    #Password finding loop
    x = 0
    for x in range(10000):
        D = ('{:04d}'.format(x) + Sha3_512RandomSalt)

        #If matching hash found inside the loop body
        #Ends immediately if found
        if hashlib.sha3_512(D.encode()).hexdigest() == hashedBenchmark:
            end = time.time()
            length = end - start
            print("Pass + Salt found: ", D)
            password = D.replace(Sha3_512RandomSalt, "")
            print("The Password :", password)
            print("The salt was: ", Sha3_512RandomSalt)
            break

    return length

def findArgon2Hash(hashedBenchmark):
    start = time.time()
    
    print("Working on cracking the Argon2id hash...")

    x = 0
    for x in range(10000):
        D = f"{x:04d}"
        currentTimeSpent = time.time()
        liveClock = currentTimeSpent - start

        print(f'Time spent {liveClock:.2f} seconds | %d' % (x / 100) + '% completed...', end='\r')

        CrackSuccessful = False
        try:
            ph.verify(hashedBenchmark, D)
            print("Matched ", D)
            end = time.time()
            length = end - start
            CrackSuccessful = True
            break
        except:
            pass
    if CrackSuccessful:
        print("Crack successful!")
    else:
        print("Crack unsuccessful Go phishing.")
    return length

RandomlySaltedMD5Time = findRandomlySaltedMD5Hash(RandomlySaltedhashedBenchmarkMD5)
RandomlySaltedSHA1Time = findRandomlySaltedSHA1Hash(RandomlySaltedhashedBenchmarkSHA1)
RandomlySaltedSHA256Time = findRandomlySaltedSHA256Hash(RandomlySaltedhashedBenchmarkSHA256)
RandomlySaltedSHA3_256Time = findRandomlySaltedSHA3_256Hash(RandomlySaltedhashedBenchmarkSHA3_256)
RandomlySaltedSHA3_512Time = findRandomlySaltedSHA3_512Hash(RandomlySaltedhashedBenchmarkSHA3_512)

#Argon2
Argon2Time = findArgon2Hash(hash_value)

print("-------- Salted --------")
print("Results: ")
print("MD5 time: ", RandomlySaltedMD5Time, "ms")
print("Sha1 time: ", RandomlySaltedSHA1Time, "ms")
print("Sha256 time: ", RandomlySaltedSHA256Time, "ms")
print("Sha3_256 time: ", RandomlySaltedSHA3_256Time, "ms")
print("Sha3_512 time: ", RandomlySaltedSHA3_512Time, "ms")
print("Argon2id time: ", Argon2Time, "ms")

#print()
#print("Argon2id ignored due to difficulties in the work environment with Python3 and Pip in Windows11")