import time
from secure_msg import encrypt

start = time.time()

encrypt("alice", "bob", "big.txt", "big.enc")

end = time.time()

print("Waktu eksekusi:", end - start, "detik")