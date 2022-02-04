import rsa
from sslib import shamir

#Generates an RSA key pair then shards it using shamir needing n of k shards to reform
def generate_keys(n, k):
    (pubKey, privKey) = rsa.newkeys(512)
    with open('CodeChallenge/keys/Public.txt', 'wb') as f:
        f.write(pubKey.save_pkcs1('PEM'))

    toShards(privKey,n,k)
    #return pubKey, privKey

def load_keys(n,k):
    with open ('CodeChallenge/keys/Public.txt', 'rb') as f:
        pubKey = rsa.PublicKey.load_pkcs1(f.read())

    with open ('CodeChallenge/keys/prime_mod.txt', 'r') as f:
        prime_mod = f.read()

    dict = {}
    dict['required_shares'] = len(n)
    dict['prime_mod'] = prime_mod
    shards = []

    for shar in n:
        with open ('CodeChallenge/keys/Shard[' + str(shar-1) +'].txt', 'r') as f:
            shards.append(str(f.read()))
    
    dict['shares'] = shards

    privKey = fromShards(dict)
    
    privKey = privKey.replace("PrivateKey(","").replace(")","")
    privKey = privKey.split(",")
    privKey = rsa.PrivateKey(int(privKey[0]),int(privKey[1]),int(privKey[2]),int(privKey[3]),int(privKey[4]))
    return pubKey, privKey

def encrypt(msg, key):  
    return rsa.encrypt(msg.encode('ascii'), key)

def decrypt(ciphertext, key):
    try:
        return rsa.decrypt(ciphertext, key).decode('ascii')
    except:
        return False

#Splits private keys into shards and stores them in files
#This currently splits a given keys
def toShards(key, n, k):
    data = shamir.to_base64(shamir.split_secret(str(key).encode('ascii'), n, k))
    shards = data.get("shares")
    required_shares = n
    prime_mod = data.get("prime_mod")

    with open('CodeChallenge/keys/prime_mod.txt', 'w') as f:
        f.write(str(prime_mod))

    for x in range(k):
        with open('CodeChallenge/keys/Shard[' + str(x) +'].txt', 'w') as f:
            f.write(str(shards[x]))
    
    return n,k

#Returns the private key
def fromShards(d):
    data = d
    return shamir.recover_secret(shamir.from_base64(data)).decode('ascii')

generate_keys(2,5)
pubKey, privKey = load_keys([2,5], 5)

message = "Random String"
#input('Enter a message: ')

ciphertext = encrypt(message, pubKey)
plaintext = decrypt(ciphertext, privKey)

if plaintext:
    print(f'Plain text: {plaintext}')
else:
    print("Message failed to decrypt")