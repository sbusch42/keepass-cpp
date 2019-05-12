#pragma once


#include <string>
#include <vector>

#include <keepass-cpp/keepass-cpp_api.h>


class gcry_cipher_handle;


namespace keepass_cpp
{


/**
*  @brief
*    Stream of random data using SALSA20 cipher
*/
class KEEPASS_CPP_API Random
{
public:
    /**
    *  @brief
    *    Constructor
    */
    Random();

    /**
    *  @brief
    *    Destructor
    */
    virtual ~Random();

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
    *    Generate block of random data
    *
    *  @param[out] data
    *    Data buffer
    *  @param[in] size
    *    Size of data buffer
    */
    void generate(char * data, size_t size) const;

    /**
    *  @brief
    *    Transform data by xor with random data block
    *
    *  @param[in, out] data
    *    Data buffer
    *  @param[in] size
    *    Size of data buffer
    */
    void transform(char * data, size_t size) const;

protected:
    gcry_cipher_handle * m_context;   ///< GCrypt context
    size_t               m_blockSize; ///< Data block size
    std::vector<char>    m_key;       ///< Encryption key
    std::vector<char>    m_iv;        ///< Initialization vector
};


} // namespace keepass_cpp
