#pragma once


#include <string>
#include <vector>

#include <keepass-cpp/keepass-cpp_api.h>


class gcry_md_handle;


namespace keepass_cpp
{


/**
*  @brief
*    Hash function using SHA256
*/
class KEEPASS_CPP_API Hash
{
public:
    /**
    *  @brief
    *    Compute SHA256 hash
    *
    *  @param[in] data
    *    Data buffer
    *
    *  @return
    *    Hash code
    */
    static std::vector<char> sha256(const std::vector<char> & data);

    /**
    *  @brief
    *    Compute SHA256 hash
    *
    *  @param[in] str
    *    Data buffer
    *
    *  @return
    *    Hash code
    */
    static std::vector<char> sha256(const std::string & str);

public:
    /**
    *  @brief
    *    Constructor
    */
    Hash();

    /**
    *  @brief
    *    Destructor
    */
    virtual ~Hash();

    /**
    *  @brief
    *    Get length of hash code
    *
    *  @return
    *    Length of hash
    */
    size_t hashLength() const;

    /**
    *  @brief
    *    Add data to process
    *
    *  @param[in] buffer
    *    Pointer to buffer (must NOT be null!)
    *  @param[in] size
    *    Length of buffer
    */
    void add(const char * buffer, size_t size);

    /**
    *  @brief
    *    Process data buffer
    *
    *  @param[in] data
    *    Data buffer
    */
    Hash & operator <<(const std::vector<char> & data);

    /**
    *  @brief
    *    Process string
    *
    *  @param[in] str
    *    Data buffer
    */
    Hash & operator <<(const std::string & str);

    /**
    *  @brief
    *    Get resulting hash
    *
    *  @return
    *    Hash value
    */
    std::vector<char> hash() const;

protected:
    gcry_md_handle * m_context;    ///< GCrypt context
    size_t           m_hashLength; ///< Length of hash
};


} // namespace keepass_cpp
