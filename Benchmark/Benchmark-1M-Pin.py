#This script is constructed to study and analyze the speed at which a simple password of 4-digits can be broken using simple algorithms
#This script tests unsalted hashes, a predetermined salt for a hash, and a randomly generated salt for each hash
#This script tests the following encryptions; MD5 and SHA3-512.
#Argon2id is omited due to issues involving Windows 11 integration on the PC used

#This script is for educational purposes
#You may use this script for educational, analytical, and ethical hacking purposes
#You may not use this script maliciously
#The author takes no responsibility over any malicious use

#Authored by Birk Jederstrom

import hashlib, time, secrets
from argon2 import PasswordHasher

pword = '9999999'

#Unsalted Hash
hashedMD5 = hashlib.md5(pword.encode()).hexdigest()

#Predetermined Salt
FixedSalt = 'foobar'

#Salted Hash
SaltedHashedMD5 = hashlib.md5((pword + FixedSalt).encode()).hexdigest()

#Randomly generated Salt
Salt = secrets.token_hex(16)

#Randomly salted Hash
RandomlySaltedhashedSHA3_512 = hashlib.sha3_512((pword + Salt).encode()).hexdigest()

#Argon2 Hash
ph = PasswordHasher()
hash_value = ph.hash('9999999')

def findMD5Hash(hashedBenchmark):
    start = time.time()

    x = 0
    for x in range(10000000):
        D = '{:07}'.format(x)

        if hashlib.md5(D.encode()).hexdigest() == hashedBenchmark:
            end = time.time()
            length = end - start
            print("Pass found ", D)
            break
    return length

def findSaltedMD5Hash(hashedBenchmark):
    start = time.time()

    x = 0
    for x in range(10000000):
        D = ('{:07}'.format(x) + FixedSalt)

        if hashlib.md5(D.encode()).hexdigest() == hashedBenchmark:
            end = time.time()
            length = end - start
            print("Pass + salt found: ", D)
            password = D.replace(FixedSalt, "")
            print("The Password: ", password)
            print("The salt was: ", FixedSalt)
            break
    return length

def findRandomlySaltedSHA3_512Hash(hashedBenchmark):
    start = time.time()

    x = 0
    for x in range(10000000):
        D = ('{:07}'.format(x) + Salt)

        if hashlib.sha3_512(D.encode()).hexdigest() == hashedBenchmark:
            end = time.time()
            length = end - start
            print("Pass + Salt found: ", D)
            password = D.replace(Salt, "")
            print("The Password: ", password)
            print("The salt was: ", Salt)
            break
    return length

def findArgon2Hash(hashedBenchmark):
    start = time.time()

    print('Working on cracking the Argon2id hash...')

    x = 0
    for x in range(10000000):
        D = f"{x:04d}"
        currentTimeSpent = time.time()
        liveClock = currentTimeSpent - start

        print(f'Time spent {liveClock:.2f} seconds | %d' % (x / 100000) + '% completed...', end='\r')

        CrackSuccessful = False
        try:
            ph.verify(hashedBenchmark, D)
            print("Matched ", D)
            end = time.time()
            length = end - start
            CrackSuccessful == True
            break
        except:
            pass
    if CrackSuccessful:
        print("Crack successful!", end='\r')
    else:
        print("Crack unsuccessful Go phishing.", end='\r')
    return length

MD5Time = findMD5Hash(hashedMD5)
SaltedMD5Time = findSaltedMD5Hash(SaltedHashedMD5)
RandomlySaltedSHA3_512Time = findRandomlySaltedSHA3_512Hash(RandomlySaltedhashedSHA3_512)
Argon2Time = findArgon2Hash(hash_value)

print("----- RESULTS -----")
print("MD5 time: ", MD5Time)
print("Salted MD5 time: ", SaltedMD5Time)
print("Randomly Salted SHA3-512 time: ", RandomlySaltedSHA3_512Time)
print("Argon2id time: ", Argon2Time)