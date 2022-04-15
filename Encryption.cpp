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

/* Initialize eData with a shared pointer to 'EncryptionData' */
EncryptionWrapper::EncryptionWrapper()
   :eData(std::make_unique<EncryptionData>())
{}

/* Needed for proper struct pointer deletion call */
EncryptionWrapper::~EncryptionWrapper() = default;

/* Toggle logging function calls. */
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
std::vector<std::string> EncryptionWrapper::generateKeyPair() noexcept
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

   rng.random_vec(eData->nonce, symCipher->default_nonce_length());
   const auto symKey = rng.random_vec(symCipher->minimum_keylength());

   // Convert plain text to uint8_t:
   Botan::secure_vector<uint8_t> ciphertext(plaintext.data(), plaintext.data() + plaintext.length());

   // Encrypt / authenticate the data symmetrically:
   symCipher->set_key(symKey);
   symCipher->start(eData->nonce);
   symCipher->finish(ciphertext);

   // Grab X509::PEM encoded key and create public key object:
   std::vector<uint8_t> keyPub(freinds_publickey.data(), freinds_publickey.data() + freinds_publickey.length());
   std::unique_ptr<Botan::Public_Key> kp(Botan::X509::load_key(keyPub));

   // Encrypt symmetric key:
   Botan::PK_Encryptor_EME enc(*kp, rng, "EME-OAEP(SHA-256,MGF1)");
   eData->symmetricKey = enc.encrypt(symKey, rng);


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

   // Check that user has actually set freindly pointer:
   if(feData == nullptr)
   {
      std::cerr << "\033[1;31mPlease Remeber to set ciphers nonce and symmetric key\033[0m\n" <<std::endl;
      throw std::invalid_argument("Missing Encryption data");
   }

   Botan::secure_vector<uint8_t> plaintext(Botan::hex_decode_locked(ciphertext));

   // Grab PKS8::PEM encoded key and create a private key object:
   Botan::DataSource_Memory keyPriv(privatekey);
   std::unique_ptr<Botan::Private_Key> kp(Botan::PKCS8::load_key(keyPriv));

   // Decrypt symmetric key:
   Botan::AutoSeeded_RNG rng;
   Botan::PK_Decryptor_EME asymCipher(*kp, rng, "EME-OAEP(SHA-256,MGF1)");

   // Throw user friendly error with more info:
   try
   {

      const auto symKey = asymCipher.decrypt(feData->symmetricKey);

      // Grab hex_encode'd string, decode, and decrypt:
      auto symCipher = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::DECRYPTION);
      symCipher->set_key(symKey);
      symCipher->start(feData->nonce);
      symCipher->finish(plaintext);

   }

   catch(Botan::Decoding_Error& exception)
   {
      std::cerr << "\033[1;31mError decrypting cipher text\033[0m" << std::endl;
      throw std::invalid_argument("Incorrect symmetric or private key used");
   }

   // Clear data from freindly container:
   feData.reset();

   return std::string(begin(plaintext), end(plaintext));
}

/*
 * @returns: eData{unique_ptr<EncryptionData>} current ciphers encryption data.
 */
std::unique_ptr<EncryptionData> EncryptionWrapper::getEncryptionData()
{
   return std::move(eData);
}

/*
 * Sets 'EncryptionData' used in encryption of cipher text, in-order to be decrypted.
 * @params: _feData{unique_ptr<EncryptionData>} struct containing cipher's encryption data.
 */
void EncryptionWrapper::setEncryptionData(std::unique_ptr<EncryptionData> _feData)
{
   feData = std::move(_feData);
}

/*
 * Sets encryption data from cipher text.
 * @params: symmetric_key{string&&} key used in encryption of text.
 *          nonce{string&&} random number used in encryption.
 */
void EncryptionWrapper::setFEdata(std::string&& symmetric_key, std::string&& nonce)
{
   feData = std::make_unique<EncryptionData>();

   feData->symmetricKey = std::vector<uint8_t>(symmetric_key.data(), symmetric_key.data() + symmetric_key.length());
   feData->nonce = std::vector<uint8_t>(nonce.data(), nonce.data() + nonce.length());
}

/*
 * Sets encryption data from cipher text.
 * @params: symmetric_key{string&&} key used in encryption of text.
 *          nonce{string&&} random number used in encryption.
 */
void EncryptionWrapper::setFEdata(std::vector<uint8_t>&& symmetric_key, std::vector<uint8_t>&& nonce)
{
   feData = std::make_unique<EncryptionData>(symmetric_key, nonce);
}
