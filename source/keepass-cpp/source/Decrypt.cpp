#include <keepass-cpp/Decrypt.h>

#include <cstdint>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <sstream>

#include <gcrypt.h>

#include <keepass-cpp/Hash.h>


namespace
{


void handleError(const gcry_error_t & err)
{
    std::string error  = gcry_strerror(err);
    std::string source = gcry_strsource(err);

    std::cout << "ERROR: " << error << std::endl;
}


}


namespace keepass_cpp
{


Decrypt::Decrypt()
: m_context(0)
, m_blockSize(0)
{
    gcry_error_t error;

    // Initialize gcrypt context
    error = gcry_cipher_open(&m_context, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0);
    if (error != 0) handleError(error);

    // Get block size
    error = gcry_cipher_algo_info(GCRY_CIPHER_AES256, GCRYCTL_GET_BLKLEN, nullptr, &m_blockSize);
    if (error != 0) handleError(error);
}

Decrypt::~Decrypt()
{
}

size_t Decrypt::blockSize() const
{
    return m_blockSize;
}

const std::vector<char> & Decrypt::key() const
{
    // Return encryption key
    return m_key;
}

void Decrypt::setKey(const std::vector<char> & key)
{
    // Save encryption key
    m_key = key;

    // Set encryption key
    gcry_error_t error = gcry_cipher_setkey(m_context, m_key.data(), m_key.size());
    if (error != 0) handleError(error);
}

const std::vector<char> & Decrypt::initializationVector() const
{
    // Return initialization vector
    return m_iv;
}

void Decrypt::setInitializationVector(const std::vector<char> & iv)
{
    // Save initialization vector
    m_iv = iv;

    // Set initialization vector
    gcry_error_t error = gcry_cipher_setiv(m_context, m_iv.data(), m_iv.size());
    if (error != 0) handleError(error);
}

void Decrypt::decrypt(char * data, size_t size) const
{
    // Decrypt data
    gcry_error_t error = gcry_cipher_decrypt(m_context, data, size, nullptr, 0);
    if (error != 0) handleError(error);
}

void Decrypt::decrypt(char * out, size_t outSize, const char * in, size_t inSize) const
{
    // Decrypt data
    gcry_error_t error = gcry_cipher_decrypt(m_context, out, outSize, in, inSize);
    if (error != 0) handleError(error);
}


} // namespace keepass_cpp
