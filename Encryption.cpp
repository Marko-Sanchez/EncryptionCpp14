#include "Encryption.hpp"

#include <botan/bcrypt.h>
#include <botan/aead.h>
#include <botan/x509_key.h>
#include <botan/pkcs8.h>
#include <botan/auto_rng.h>
#include <botan/rsa.h>
#include <botan/pubkey.h>
#include <botan/hex.h>
#include <botan/data_src.h>


/*
 * Holds information used for encrypting a message.
 * @values:
 *          symmetricKey: encrypted sym key used for AEAD of cipher text.
 *          nonce: one time random number used in encryption of cipher text.
 */
struct EncryptionWrapper::EncryptionInfo
{
   std::vector<uint8_t> symmetricKey;
   std::vector<uint8_t> nonce;
};

/* Initialize EncryptionInfo struct */
EncryptionWrapper::EncryptionWrapper()
:eInfo(std::make_unique<EncryptionInfo>())
{}

/* Needed for proper struct pointer deletion call */
EncryptionWrapper::~EncryptionWrapper() = default;

/*
 * Toggle logging function calls.
 */
void EncryptionWrapper::logging()
{
   logFunctions = !logFunctions;
}

/*
 * Takes in a const string& of at most 72 characters, generates a bcrypt hash.
 * @params: password: user password.
 * @returns: hashed password.
 */
std::string EncryptionWrapper::passwordEncryption(const std::string& password)const
{
   if(logFunctions)
      logAndProccess(__PRETTY_FUNCTION__);

   Botan::AutoSeeded_RNG rng;    // Random number generator:
   uint16_t work_factor = 12;    // How much work to do to prevent guessing attacks:
   char version = 'a';

   return std::string{Botan::generate_bcrypt(password, rng, work_factor, version)};
}

/* Checks if password and bcrypt hash match.
 * @params: password{const string&} users password.
 *          hash{const string&} potential password hash.
 * @returns: true if match
 */
bool EncryptionWrapper::passwordChecker(const std::string& password, const std::string& hash)const
{

   if(logFunctions)
      logAndProccess(__PRETTY_FUNCTION__);

   return Botan::check_bcrypt(password, hash);
}

/*
 * Creates RSA private and public key.
 * @returns: {vector<string>} containing private and public RSA key's.
 */
std::vector<std::string> EncryptionWrapper::generatePairKey() noexcept
{
   if(logFunctions)
      logAndProccess(__PRETTY_FUNCTION__);

   Botan::AutoSeeded_RNG rng;
   Botan::RSA_PrivateKey keyPair(rng, 1024);

   std::string privatekey = Botan::PKCS8::PEM_encode(keyPair);
   std::string publickey = Botan::X509::PEM_encode(keyPair);

   return {privatekey, publickey};
}

/*
 * Encrypts message using authenticated symmetric key, then encrypts
 * symmetric key using freinds public key.
 * @params: plaintext{const string&} content to be encrypted.
 *          key{const string&} freinds public key.
 * @returns: outputs cipher text.
 */
std::string EncryptionWrapper::messageEncryption(const std::string& plaintext, const std::string& freinds_publickey)
{

   if(logFunctions)
      logAndProccess(__PRETTY_FUNCTION__);

   auto symCipher = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::ENCRYPTION);

   // Create a random nonce:
   Botan::AutoSeeded_RNG rng;

   rng.random_vec(eInfo->nonce, symCipher->default_nonce_length());
   const auto symKey = rng.random_vec(symCipher->minimum_keylength());

   // Convert plain text to uint8_t:
   Botan::secure_vector<uint8_t> ciphertext(plaintext.data(), plaintext.data() + plaintext.length());

   // Encrypt / authenticate the data symmetrically:
   symCipher->set_key(symKey);
   symCipher->start(eInfo->nonce);
   symCipher->finish(ciphertext);

   // Grab X509::PEM encoded key and create public key object:
   std::vector<uint8_t> keyPub(freinds_publickey.data(), freinds_publickey.data() + freinds_publickey.length());
   std::unique_ptr<Botan::Public_Key> kp(Botan::X509::load_key(keyPub));

   // Encrypt symmetric key:
   Botan::PK_Encryptor_EME enc(*kp, rng, "EME-OAEP(SHA-256,MGF1)");
   eInfo->symmetricKey = enc.encrypt(symKey, rng);


   return Botan::hex_encode(ciphertext);
}

/*
 * Decrypts users symmetric key using private key, which will then decrypt
 * cipher text using authenitcated encryption.
 * @params: ciphertext{const string&} hex encoded string to e decrypted.
 *          privateKey{const string&} users private key.
 * @returns: decrypted text.
 */
std::string EncryptionWrapper::messageDecryption(const std::string& ciphertext, const std::string& privatekey)
{
   if(logFunctions)
      logAndProccess(__PRETTY_FUNCTION__);

   Botan::secure_vector<uint8_t> plaintext(Botan::hex_decode_locked(ciphertext));

   // Grab PKS8::PEM encoded key and create a private key object:
   Botan::DataSource_Memory keyPriv(privatekey);
   std::unique_ptr<Botan::Private_Key> kp(Botan::PKCS8::load_key(keyPriv));

   // Decrypt symmetric key:
   Botan::AutoSeeded_RNG rng;
   Botan::PK_Decryptor_EME asymCipher(*kp, rng, "EME-OAEP(SHA-256,MGF1)");
   const auto symKey = asymCipher.decrypt(eInfo->symmetricKey);

   // Grab hex_encode'd string, decode, and decrypt:
   auto symCipher = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::DECRYPTION);
   symCipher->set_key(symKey);
   symCipher->start(eInfo->nonce);
   symCipher->finish(plaintext);

   return std::string(begin(plaintext), end(plaintext));
}
