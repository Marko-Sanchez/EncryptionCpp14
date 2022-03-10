#pragma once
#include <memory>

class Encrypt{
    public:
        Encrypt();

        ~Encrypt();

        /* Displays 'Hello, World' for testing */
        void greeting();

        /* Using Botan-2 example code to check botan in configured
         * correctly
         * */
        void encrypt();
    private:
        /* Forward declare struct */
        struct Impl;
        std::unique_ptr<Impl> pImpl;
};
