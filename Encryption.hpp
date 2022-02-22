#pragma once
#include <memory>

class Encrypt{
    public:
        Encrypt();
        ~Encrypt();
        void greeting();
    private:
        struct Impl;
        std::unique_ptr<Impl> pImpl;
};
