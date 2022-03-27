#include "Encryption.hpp"
#include <iostream>

int main(int argc, char* argv[])
{
    // Encryption wrapper:
    EncryptionWrapper ew;

    // Hash password:
    std::string password{"myPassword"};
    std::string hash{ew.passwordEncryption(password)};

    // Ouput password and it's hash:
    std::cout << "Password: " << password << std::endl;
    std::cout << "Hash: " << hash << std::endl;

    if(ew.passwordChecker(password, hash))
        std::cout << "Passwords matches hash." << std::endl << std::endl;


    // Compare an old hash of current password to check compatability:
    if(argc >= 2)
    {
        std::string oldHash{argv[1]};

        std::cout << oldHash << std::endl;
        std::cout << "Password matches with old hash: "<< ew.passwordChecker(password, oldHash) << std::endl;
        std::cout << std::endl;
    }

    // Generate private key:
    std::vector<std::string> keyPair{ew.generatePairKey()};

    // Test message encryption:
    const std::string plaintext{"Hello world from somewhere I don't know"};

    //Grab Keys:
    const std::string private_key{keyPair[0]};
    const std::string public_key{keyPair[1]};

    std::string ciphertext{ew.messageEncryption(plaintext, public_key)};

    std::string text{ew.messageDecryption(ciphertext, private_key)};


    std::cout << "Encryption: " << ciphertext << std::endl
              << "Decryption: " << text << std::endl;
    std::cout << std::endl;

    // Create new user:
    ew.createUser(std::string("Marko"), std::string("mountainDew"));
    std::cout << std::endl;

#if 0
     /* Testing pusedo-comunication between two individuals */

    EncryptionWrapper ewA;      // Alice's Wrapper:
    EncryptionWrapper ewB;      // Bob's Wrapper:

    // Generate Key pair for self:
    std::vector<std::string> BobsKeypair{ewB.generatePairKey()};

    // Generate Key pair for other person:
    std::vector<std::string> AliceKeypair{ewA.generatePairKey()};

    // Exhange public keys:
    std::string BobsPublicKey{BobsKeypair[1]};
    std::string AlicePublicKey{AliceKeypair[1]};

    std::string AliceMessage{"Hi Bob, how are you?"};
    std::string BobsMessage{"I'm doing well thanks for asking."};

    // Alice encrypts message to send to Bob:
    std::string AliceCipherText{ewA.messageEncryption(AliceMessage, BobsPublicKey)};

    // Bob decrypts Alice message:
    std::string AlicePlainText{ewB.messageDecryption(AliceCipherText, BobsKeypair[0])};
    std::cout << AlicePlainText << std::endl;

    // Bob responds:
    std::string BobCipherText{ewB.messageEncryption(BobsMessage, AlicePublicKey)};

    // Alice decrypts Bob's message:
    std::string BobPlainText{ewA.messageDecryption(BobCipherText, AliceKeypair[0])};
    std::cout << BobPlainText << std::endl;

    // Nonce needs to be exhanged inorder to work:
    // And also the symmetricKey which is hashed:
#endif

    return EXIT_SUCCESS;
}
