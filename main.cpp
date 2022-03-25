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
    if(argc >= 3 and true)
    {
        std::string oldHash{argv[2]};

        std::cout << oldHash << std::endl;
        std::cout << "Password matches with old hash: "<< ew.passwordChecker(password, oldHash) << std::endl;
    }

    // Generate private key:
    std::vector<std::string> keyPair{ew.generatePKey()};

    // Test message encryption:
    const std::string plaintext{"Hello world from somewhere I don't know"};

    //Grab Keys:
    const std::string private_key{keyPair[0]};
    const std::string public_key{keyPair[1]};

    std::string ciphertext{ew.messageEncryption(plaintext, public_key)};
    std::string text{ew.messageDecryption(ciphertext, private_key)};


    std::cout << "Encryption: " << ciphertext << std::endl
              << "Decryption: " << text << std::endl;

    // Create new user:
    ew.createUser(std::string("Marko"), std::string("mountainDew"));

    return EXIT_SUCCESS;
}
