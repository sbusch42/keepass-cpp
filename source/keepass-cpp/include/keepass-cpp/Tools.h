#pragma once


#include <string>
#include <vector>

#include <keepass-cpp/keepass-cpp_api.h>


namespace keepass_cpp
{


/**
*  @brief
*    Tools
*/
class KEEPASS_CPP_API Tools
{
public:
    /**
    *  @brief
    *    Convert data buffer into hex-string
    *
    *  @param[in] data
    *    Data buffer
    *  @param[in] size
    *    Size of data buffer
    *
    *  @return
    *    String
    */
    static std::string toHexString(const char * data, size_t size);

    /**
    *  @brief
    *    Convert data buffer into hex-string
    *
    *  @param[in] data
    *    Data buffer
    *
    *  @return
    *    String
    */
    static std::string toHexString(const std::vector<char> & data);
};


} // namespace keepass_cpp
