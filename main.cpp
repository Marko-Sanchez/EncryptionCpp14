#include "Encryption.hpp"
#include <iostream>

int main(int argc, char* argv[])
{
    // Encryption wrapper:
    EncryptionWrapper ew;

    if(argc < 2)
    {
        // Hello world output:
        ew.greeting();

        return EXIT_SUCCESS;
    }

    // Hash password:
    std::string password{argv[1]};
    std::string hash{ew.passwordEncryption(password)};

    // Ouput password and it's hash:
    std::cout << password << std::endl;
    std::cout << hash << std::endl;

    if(ew.passwordChecker(password, hash))
        std::cout << "Passwords matches current hash." << std::endl;


    // Compare an old hash of current password to check compatability:
    if(argc >= 3 and true)
    {
        std::string oldHash{argv[2]};

        std::cout << oldHash << std::endl;
        std::cout << "Password matches with old hash: "<< ew.passwordChecker(password, oldHash) << std::endl;
    }

    return EXIT_SUCCESS;
}
