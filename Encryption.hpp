#pragma once
#include <memory>

class EncryptionWrapper{

    public:
        EncryptionWrapper();

        ~EncryptionWrapper();

        /* Displays 'Hello, World' for testing */
        void greeting();

        /* Encrypt a users password */
        std::string passwordEncryption(const std::string& password)const;

        /* Check if password is correct, by searching for it's hash in database */
        bool passwordChecker(const std::string& password)const;

        /* Check password with a given hash */
        bool passwordChecker(const std::string& password, const std::string& hash)const;

        /* Encrypts users message */
        void messageEncryption(const std::string& plaintext, const std::string& key);

    private:

        /* Log function calls */
        template<typename T>
        void logAndProccess(T&& param)const;

        /* Forward declare struct */
        struct Impl;
        std::unique_ptr<Impl> pImpl;
};
