import rsa
from sslib import shamir

#Generates an RSA key pair then shards it using shamir needing n of k shards to reform
def generate_keys(n, k):
    (pubKey, privKey) = rsa.newkeys(2048)
    with open('keys/Public.txt', 'wb') as f:
        f.write(pubKey.save_pkcs1('PEM'))

    toShards(privKey,n,k)

#Loads public from file
#Loads private key using n shards
def load_keys(n,k):
    with open ('keys/Public.txt', 'rb') as f:
        pubKey = rsa.PublicKey.load_pkcs1(f.read())

    with open ('keys/prime_mod.txt', 'r') as f:
        prime_mod = f.read()

    dict = {}
    dict['required_shares'] = len(n)
    dict['prime_mod'] = prime_mod
    shards = []

    for shar in n:
        with open ('keys/Shard[' + str(shar-1) +'].txt', 'r') as f:
            shards.append(str(f.read()))
    
    dict['shares'] = shards

    privKey = fromShards(dict)
    
    privKey = privKey.replace("PrivateKey(","").replace(")","")
    privKey = privKey.split(",")
    privKey = rsa.PrivateKey(int(privKey[0]),int(privKey[1]),int(privKey[2]),int(privKey[3]),int(privKey[4]))
    return pubKey, privKey

#Encrypts message using public key provided
def encrypt(msg, key):  
    return rsa.encrypt(msg.encode('ascii'), key)

#Decrypts the ciphertext using private key provided
def decrypt(ciphertext, key):
    try:
        return rsa.decrypt(ciphertext, key).decode('ascii')
    except:
        return False

#Splits private keys into shards and stores them in files
def toShards(key, n, k):
    data = shamir.to_base64(shamir.split_secret(str(key).encode('ascii'), n, k))
    shards = data.get("shares")
    required_shares = n
    prime_mod = data.get("prime_mod")

    with open('keys/prime_mod.txt', 'w') as f:
        f.write(str(prime_mod))

    for x in range(k):
        with open('keys/Shard[' + str(x) +'].txt', 'w') as f:
            f.write(str(shards[x]))
    
    return n,k

#Returns the private key using a provided data dictionary
def fromShards(d):
    data = d
    return shamir.recover_secret(shamir.from_base64(data)).decode('ascii')

if __name__ == '__main__':
    print("Welcome to sharding RSA private keys")
    message = input('Enter a message: ')
    n = 10
    k = 1
    while(n > k):
        k = input("Please enter the number of shards the private key should be split into: ")
        n = input("Please enter the number of shards it should take to reconstruct the private key: ")

    shardList = []
    while (len(shardList) < int(n)):
        shardList = input("Please enter a list of which shards should be used to reconstruct the private key (Example: 2,5): ").split(",")

    desired_array = [int(numeric_string) for numeric_string in shardList]

    print(desired_array)

    generate_keys(int(n),int(k))
    pubKey, privKey = load_keys(desired_array, int(k))

    ciphertext = encrypt(message, pubKey)
    plaintext = decrypt(ciphertext, privKey)

    if plaintext:
        print(f'Plain text: {plaintext}')
    else:
        print("Message failed to decrypt")