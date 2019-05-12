#pragma once


#include <string>
#include <memory>
#include <vector>
#include <streambuf>
#include <istream>

#include <keepass-cpp/Decrypt.h>


namespace keepass_cpp
{


/**
*  @brief
*    Input stream for encrypted data
*/
class KEEPASS_CPP_API EncryptedInputStream : public std::istream
{
public:
    /**
    *  @brief
    *    Constructor
    *
    *  @param[in] inputStream
    *    Encrypted input stream
    *  @param[in] key
    *    Decryption key
    *  @param[in] iv
    *    Initialization vector
    */
    EncryptedInputStream(std::istream & inputStream, const std::vector<char> & key, const std::vector<char> & iv);

    /**
    *  @brief
    *    Destructor
    */
    virtual ~EncryptedInputStream();

protected:
    /**
    *  @brief
    *    Constructor
    *
    *  @param[in] sb
    *    Stream buffer
    */
    EncryptedInputStream(std::streambuf * streamBuffer);

protected:
    std::unique_ptr<std::streambuf> m_streamBuffer; ///< The associated stream buffer
};


/**
*  @brief
*    Stream buffer for decrypting an input stream
*/
class KEEPASS_CPP_API EncryptedInputStreamBuffer : public std::streambuf
{
public:
    /**
    *  @brief
    *    Constructor
    *
    *  @param[in] inputStream
    *    Encrypted input stream
    *  @param[in] key
    *    Decryption key
    *  @param[in] iv
    *    Initialization vector
    *  @param[n] bufferSize
    *    Size of the read buffer
    *  @param[n] putbackSize
    *    Size of the putback area
    */
    EncryptedInputStreamBuffer(std::istream & inputStream, const std::vector<char> & key, const std::vector<char> & iv, size_t bufferSize = 32 * 1024, size_t putbackSize = 128);

    /**
    *  @brief
    *    Destructor
    */
    virtual ~EncryptedInputStreamBuffer();

    // Virtual streambuf functions
    virtual std::streambuf::int_type underflow() override;

protected:
    Decrypt             m_decrypt;     ///< Decryptor
    std::istream      & m_inputStream; ///< Encrypted input stream
    const size_t        m_bufferSize;  ///< Size of the data buffer
    const size_t        m_putbackSize; ///< Size of the putback area
    std::vector<char>   m_buffer;      ///< Read buffer
};


} // namespace keepass_cpp
