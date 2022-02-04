import unittest
import genesisCodeChallenge

class TestShamir(unittest.TestCase):

    def test_shamir(self):

        #Generate Keys calls the shamir function and splits the private key into k shard
        genesisCodeChallenge.generate_keys(2,5)
        
        #Load keys calls the fromShards function and retrieves the privte key using a list of what shards to use
        pubKey, privKey = genesisCodeChallenge.load_keys([2,5], 5)

        message = "Random String"
        #input('Enter a message: ')

        ciphertext = genesisCodeChallenge.encrypt(message, pubKey)
        plaintext = genesisCodeChallenge.decrypt(ciphertext, privKey)

        self.assertTrue(message, plaintext)

if __name__ == '__main__':
    unittest.main()