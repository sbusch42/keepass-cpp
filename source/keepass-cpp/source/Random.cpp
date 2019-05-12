#include <keepass-cpp/Random.h>

#include <cstdint>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <sstream>

#include <gcrypt.h>

#include <keepass-cpp/Hash.h>
#include <keepass-cpp/Tools.h>


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


Random::Random()
: m_context(0)
, m_blockSize(0)
{
    gcry_error_t error;

    // Initialize gcrypt context
    error = gcry_cipher_open(&m_context, GCRY_CIPHER_SALSA20, GCRY_CIPHER_MODE_STREAM, 0);
    if (error != 0) handleError(error);

    // Get block size
    error = gcry_cipher_algo_info(GCRY_CIPHER_SALSA20, GCRYCTL_GET_BLKLEN, nullptr, &m_blockSize);
    if (error != 0) handleError(error);
}

Random::~Random()
{
}

size_t Random::blockSize() const
{
    return m_blockSize;
}

const std::vector<char> & Random::key() const
{
    // Return encryption key
    return m_key;
}

void Random::setKey(const std::vector<char> & key)
{
    // Save encryption key
    m_key = key;

    // Set encryption key
    gcry_error_t error = gcry_cipher_setkey(m_context, m_key.data(), m_key.size());
    if (error != 0) handleError(error);
}

const std::vector<char> & Random::initializationVector() const
{
    // Return initialization vector
    return m_iv;
}

void Random::setInitializationVector(const std::vector<char> & iv)
{
    // Save initialization vector
    m_iv = iv;

    // Set initialization vector
    gcry_error_t error = gcry_cipher_setiv(m_context, m_iv.data(), m_iv.size());
    if (error != 0) handleError(error);
}

void Random::generate(char * data, size_t size) const
{
    // Fill buffer with random data
    for (size_t i=0; i<size; i++) {
        char byte = 0;

        // Get next random number
        gcry_error_t error = gcry_cipher_encrypt(m_context, &byte, 1, nullptr, 0);
        if (error != 0) handleError(error);

        // Write result
        data[i] = byte;
    }
}

void Random::transform(char * data, size_t size) const
{
    // Get random data block of the same size as the data
    std::vector<char> randomData(size, 0);
    generate(randomData.data(), size);

    // XOR data with random
    for (size_t i=0; i<size; i++) {
        data[i] = data[i] ^ randomData[i];
    }
}


} // namespace keepass_cpp
