#include "Encryption.hpp"
#include <string>
#include <iostream>

struct Encrypt::Impl
{
    std::string greeting = "Hello World, from inside Class\n";
};

Encrypt::Encrypt()
: pImpl(std::make_unique<Impl>())
{}

Encrypt::~Encrypt() = default;

void Encrypt::greeting()
{
    std::cout << pImpl->greeting;
}
