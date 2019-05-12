#pragma once


#include <string>
#include <vector>

#include <keepass-cpp/keepass-cpp_api.h>


class gcry_cipher_handle;


namespace keepass_cpp
{


/**
*  @brief
*    Encryption using AES256 cipher
*/
class KEEPASS_CPP_API Encrypt
{
public:
    /**
    *  @brief
    *    Constructor
    */
    Encrypt();

    /**
    *  @brief
    *    Destructor
    */
    virtual ~Encrypt();

    /**
    *  @brief
    *    Get block size
    *
    *  @return
    *    Block size
    */
    size_t blockSize() const;

    /**
    *  @brief
    *    Get key
    *
    *  @return
    *    Encryption key
    */
    const std::vector<char> & key() const;

    /**
    *  @brief
    *    Set key
    *
    *  @param[in] key
    *    Encryption key
    */
    void setKey(const std::vector<char> & key);

    /**
    *  @brief
    *    Get initialization vector
    *
    *  @return
    *    Initialization vector
    */
    const std::vector<char> & initializationVector() const;

    /**
    *  @brief
    *    Set initialization vector
    *
    *  @param[in] iv
    *    Initialization vector
    */
    void setInitializationVector(const std::vector<char> & iv);

    /**
    *  @brief
    *    Encrypt data
    *
    *  @param[in,out] data
    *    Data buffer
    *  @param[out] size
    *    Size of buffer
    */
    void encrypt(char * data, size_t size) const;

    /**
    *  @brief
    *    Encrypt data
    *
    *  @param[out] out
    *    Output buffer
    *  @param[out] outSize
    *    Size of output buffer
    *  @param[in] data
    *    Input in
    *  @param[out] inSize
    *    Size of input buffer
    */
    void encrypt(char * out, size_t outSize, const char * in, size_t inSize) const;

protected:
    gcry_cipher_handle * m_context;   ///< GCrypt context
    size_t               m_blockSize; ///< Data block size
    std::vector<char>    m_key;       ///< Encryption key
    std::vector<char>    m_iv;        ///< Initialization vector
};


} // namespace keepass_cpp
