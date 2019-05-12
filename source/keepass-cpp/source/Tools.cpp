#include <keepass-cpp/Tools.h>

#include <sstream>
#include <iomanip>


namespace keepass_cpp
{


std::string Tools::toHexString(const char * data, size_t size)
{
    std::ostringstream os;

    // Convert each byte into string
    for (size_t i=0; i<size; i++) {
        os << std::setfill('0') << std::setw(2) << std::hex << static_cast<int>(data[i] & 255);
    }

    // Return hex-string
    return os.str();
}

std::string Tools::toHexString(const std::vector<char> & data)
{
    return toHexString(data.data(), data.size());
}


} // namespace keepass_cpp
