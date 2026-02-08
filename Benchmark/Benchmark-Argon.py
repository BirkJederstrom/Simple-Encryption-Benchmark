import time
import hashlib
from argon2 import PasswordHasher

ph = PasswordHasher()
hash_value = ph.hash("1234")

print(hash_value)

def findArgon2Hash(hashedBenchmark):
    start = time.time()

    x = 0
    for x in range(1500):
        attempt = f"{x:04d}"
        print(attempt)
        try:
            ph.verify(hashedBenchmark, attempt)
            print("Matched ", attempt)
            end = time.time()
            length = end - start
            break
        except:
            pass

    return length

time_spent = findArgon2Hash(hash_value)

print("The time spent to crack this hash was: ", time_spent)
