#pragma once
#include <memory>
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <chrono>
#include <ctime>

class EncryptionWrapper{

    public:

        /* Create user, encrypts password and stores it in a file */
        template<typename T, typename K>
        void createUser(T&& username, K&& plainPassword);

        /* Generate a private key */
        std::vector<std::string> generatePKey();

        /* Encrypt a users password */
        std::string passwordEncryption(const std::string& password)const;

        /* Check password with a given hash */
        bool passwordChecker(const std::string& password, const std::string& hash)const;

        /* Encrypts users message */
        std::string messageEncryption(const std::string& plaintext, const std::string& publickey);

        /* Decrypts recieved message */
        std::string messageDecryption(const std::string& ciphertext, const std::string& privatekey);

    private:

        /* Log function calls */
        template<typename T>
        void logAndProccess(T&& param)const;
};

               /*    Template Functions   */

/*
 * Associates a username with an encrpyted password and stores information:
 * @params: _username{ type string}.
 *          plainPassword{type string} password to be encrpyted.
 * @returns: if new user adds username and encrpyted password to file.
 */
template<typename T, typename K>
void EncryptionWrapper::createUser(T&& _username, K&& _plainPassword)
{

   // Perfect forward to avoid having multiple copies around:
   std::string username{std::forward<T>(_username)};
   std::string password{std::forward<K>(_plainPassword)};

   std::fstream fs("passwords", std::fstream::in | std::fstream::out | std::fstream::app);
   std::string line;

   // Iterate file and grab usernames:
   while(std::getline(fs, line))
   {

      auto found = line.find(' ');
      if(found != std::string::npos)
      {

         // If user alredy exist warn and exit:
         if(line.compare(0, found, username) == 0)
         {
            std::cout << "User " << username << " already exist" << std::endl;
            return;
         }

      }
   }

   // User does not exist therefore, create and store hashed password:
   if(fs.is_open())
   {
      // Reset file pointer:
      fs.clear();

      fs << username << ' ' << passwordEncryption(password) << '\n';
      std::cout << "Added user: " << username << std::endl;
      fs.close();
   }

   // log function call:
   logAndProccess(__PRETTY_FUNCTION__);
}

/*
 * Takes in a universal refrences and logs param.
 * @warning: not thread safe.
 * @params: name of subject to be logged.
 * @retuns: writes current date and subject to file.
 */
template<typename T>
void EncryptionWrapper::logAndProccess(T&& param)const
{
   auto now = std::chrono::system_clock::now();
   auto time = std::chrono::system_clock::to_time_t(now);

   std::ofstream fs;
   fs.open("functionLogs", std::fstream::out | std::ofstream::app);

   // Format and write to buffer:
   fs << ctime(&time) << ' ' << param << '\n';

   // Write to file and close:
   fs.close();
}
