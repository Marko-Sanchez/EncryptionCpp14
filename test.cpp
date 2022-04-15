#include "Encryption.hpp"
#include <iostream>

int main(int argc, char* argv[])
{
    // Encryption wrapper:
    EncryptionWrapper ew;

    // Hash password:
    std::string password{"Stacy you smell"};
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
    std::vector<std::string> keyPair{ew.generateKeyPair()};

    // Test message encryption:
    const std::string plaintext{"Hello world from somewhere I don't know"};

    //Grab Keys:
    const std::string private_key{keyPair[0]};
    const std::string public_key{keyPair[1]};

    std::string ciphertext{ew.messageEncryption(plaintext, public_key)};

    // Pass EncryptionData to self:
    ew.setEncryptionData(ew.getEncryptionData());

    std::string text{ew.messageDecryption(ciphertext, private_key)};


    std::cout << "Encryption: " << ciphertext << std::endl
              << "Decryption: " << text << std::endl;
    std::cout << std::endl;

    // Create new user:
    ew.createUser(std::string("Marko"), std::string("mountainDew"));
    std::cout << std::endl;

#if 1
     /* Testing pusedo-comunication between two individuals */

    EncryptionWrapper ewA;      // Alice's Wrapper:
    EncryptionWrapper ewB;      // Bob's Wrapper:

    // Generate Key pair for self:
    std::vector<std::string> BobsKeypair{ewB.generateKeyPair()};

    // Generate Key pair for other person:
    std::vector<std::string> AliceKeypair{ewA.generateKeyPair()};

    // Exhange public keys:
    std::string BobsPublicKey{BobsKeypair[1]};
    std::string AlicePublicKey{AliceKeypair[1]};

    std::string AliceMessage{"Hi Bob, how are you?"};
    std::string BobsMessage{"I'm doing well thanks for asking."};

    // Alice encrypts message to send to Bob:
    std::string AliceCipherText{ewA.messageEncryption(AliceMessage, BobsPublicKey)};

    // Pass encryption data:
    std::unique_ptr<EncryptionData> Adata = ewA.getEncryptionData();
    ewB.setEncryptionData(std::move(Adata));

    // Bob decrypts Alice message:
    std::string AlicePlainText{ewB.messageDecryption(AliceCipherText, BobsKeypair[0])};
    std::cout << AlicePlainText << std::endl;

    // Bob responds:
    std::string BobCipherText{ewB.messageEncryption(BobsMessage, AlicePublicKey)};

    // pass data: different method.
    auto Bdata = ewB.getEncryptionData();

    ewA.setFEdata(std::move(Bdata->symmetricKey), std::move(Bdata->nonce));

    // Alice decrypts Bob's message:
    std::string BobPlainText{ewA.messageDecryption(BobCipherText, AliceKeypair[0])};
    std::cout << BobPlainText << std::endl;

#endif

    std::cout << std::endl;

    /* Error checking */
    EncryptionWrapper dale;
    EncryptionWrapper marry;

    auto dalesKeys = dale.generateKeyPair();
    auto marrysKeys = marry.generateKeyPair();

    // Test case 1: marry uses in-correct symmetric key:
    std::string pmsg1{"Mountain dew, shaken not stirred please."};
    std::string cmsg1{dale.messageEncryption(pmsg1, marrysKeys[1])};

    // marry get's dale encryption info:
    auto daleInfo = dale.getEncryptionData();

    //  dale's symmetric key get's corrupted or something happens to it and get's replaced:
    for(auto& i: daleInfo->symmetricKey)
        i = 9;

    // marry set's dales information to friendly object to be decrypted:
    marry.setEncryptionData(std::move(daleInfo));

    try
    {

    // marry tries to decrypt cipher text:
    std::string pmsg2{marry.messageDecryption(cmsg1, marrysKeys[0])};

    }
    catch(std::invalid_argument& exception)
    {
        std::cout << exception.what() << std::endl;
    }

    return EXIT_SUCCESS;
}
