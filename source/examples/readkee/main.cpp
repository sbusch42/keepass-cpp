
#include <iostream>

#include <keepass-cpp/KeePassLoader.h>


using namespace keepass_cpp;


int main(int argc, char *argv[])
{
    // Check parameters
    if (argc != 2) {
        std::cout << std::endl;
        std::cout << "Usage: readkee <file>" << std::endl;
        std::cout << std::endl;
        return 1;
    }

    // Get filename
    std::string filename = argv[1];
    std::cout << "Reading from '" << filename << "'" << std::endl;

    // Get password
    std::string password = "";
    std::cout << "Password: ";
    std::cin >> password;
    std::cout << std::endl;

    // Open keepass file
    KeePassLoader keepass;
    keepass.load(filename, password);

    // Done
    return 0;
}
