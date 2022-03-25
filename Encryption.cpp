#include "Encryption.hpp"

#include <botan/bcrypt.h>
#include <botan/x509_key.h>
#include <botan/pkcs8.h>
#include <botan/auto_rng.h>
#include <botan/rsa.h>
#include <botan/botan.h>
#include <botan/pk_keys.h>
#include <botan/pubkey.h>
#include <botan/hex.h>

/*
 * Takes in a const string& of at most 72 characters, generates a bcrypt hash.
 * @params: password: user password.
 * @returns: hashed password.
 */
std::string EncryptionWrapper::passwordEncryption(const std::string& password)const
{
   Botan::AutoSeeded_RNG rng;    // Random number generator:
   uint16_t work_factor = 12;    // How much work to do to prevent guessing attacks:
   char version = 'a';

   logAndProccess(__PRETTY_FUNCTION__);

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
   logAndProccess(__PRETTY_FUNCTION__);

   return Botan::check_bcrypt(password, hash);
}

/*
 * Creates RSA private and public key.
 * @returns: {vector<string>} containing private and public RSA key's.
 */
std::vector<std::string> EncryptionWrapper::generatePKey()
{
   Botan::AutoSeeded_RNG rng;
   Botan::RSA_PrivateKey keyPair(rng, 1024);

   std::string privatekey = Botan::PKCS8::PEM_encode(keyPair);
   std::string publickey = Botan::X509::PEM_encode(keyPair);

   return {privatekey, publickey};
}

/*
 * Encrypts message using EME1(SHA-256).
 * @params: plaintext{const string&} content to be encrypted.
 *          key{const string&} callees public key.
 * @returns: outputs cipher text.
 */
std::string EncryptionWrapper::messageEncryption(const std::string& plaintext, const std::string& publickey)
{
   Botan::AutoSeeded_RNG rng;
   Botan::DataSource_Memory keyPub(publickey);

   // Grab X509::PEM encoded key and create public key object:
   std::unique_ptr<Botan::Public_Key> kp(Botan::X509::load_key(keyPub));
   Botan::PK_Encryptor_EME enc(*kp, rng, "EME1(SHA-256)");

   // Convert string to uint8_t and encrypt:
   std::vector<uint8_t> pt(plaintext.data(), plaintext.data() + plaintext.length());
   std::vector<uint8_t> ciphertext = enc.encrypt(pt, rng);

   return Botan::hex_encode(ciphertext);
}

/*
 * Decrypts recieved message using EME1(SHA-256)
 * @params: ciphertext{const string&} hex encoded string to e decrypted.
 *          privateKey{const string&} users private key.
 * @returns: decrypted text.
 */
std::string EncryptionWrapper::messageDecryption(const std::string& ciphertext, const std::string& privatekey)
{
   Botan::AutoSeeded_RNG rng;
   Botan::DataSource_Memory keyPriv(privatekey);

   // Grab PKS8::PEM encoded key and create a private key object:
   std::unique_ptr<Botan::Private_Key> kp(Botan::PKCS8::load_key(keyPriv));
   Botan::PK_Decryptor_EME dec(*kp, rng, "EME1(SHA-256)");

   // Grab hex_encode'd string, decode, and decrypt:
   Botan::secure_vector<uint8_t> ct(Botan::hex_decode_locked(ciphertext));
   std::vector<uint8_t> temptext = Botan::unlock(dec.decrypt(ct));

   return std::string(begin(temptext), end(temptext));
}
