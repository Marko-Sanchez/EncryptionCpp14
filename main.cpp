#include "Encryption.hpp"
#include <iostream>

int main(int argc, char* argv[])
{
    if( argc < 2)
    {
        Encrypt e;
        // Test encrypt default code:
        e.encrypt();

        return EXIT_SUCCESS;
    }
    std::cout << argv[1] << std::endl;
    return EXIT_SUCCESS;
}
