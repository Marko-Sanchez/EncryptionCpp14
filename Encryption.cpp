#include "Encryption.hpp"
#include <string>
#include <iostream>

#include <botan/bcrypt.h>
#include <botan/auto_rng.h>

struct EncryptionWrapper::Impl
{
    std::string greeting = "Hello World, from inside Class\n";
};

EncryptionWrapper::EncryptionWrapper()
: pImpl(std::make_unique<Impl>())
{}

EncryptionWrapper::~EncryptionWrapper() = default;

void EncryptionWrapper::greeting()
{
    std::cout << pImpl->greeting;
}

/*
 * Takes in a const string& of at most 72 characters, generats a bcrypt hash.
 * @params: password: user password.
 * @returns: hashed password.
 */
std::string EncryptionWrapper::passwordEncryption(const std::string& password)const
{
   Botan::AutoSeeded_RNG rng;    // Random number generator:
   uint16_t work_factor = 12;    // How much work to do to prevent guessing attacks:
   char version = 'a';

   std::string passwordHash{Botan::generate_bcrypt(password, rng, work_factor, version)};

   return passwordHash;
}

/* Checks if password and bcrypt hash match.
 * @params: password{const string&} users password.
 *          hash{const string&} potential password hash.
 * @returns: true if match
 */
bool EncryptionWrapper::passwordChecker(const std::string& password, const std::string& hash)const
{
   return Botan::check_bcrypt(password, hash);
}
