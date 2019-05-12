#include <keepass-cpp/Hash.h>

#include <iostream>

#include <gcrypt.h>


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


std::vector<char> Hash::sha256(const std::vector<char> & data)
{
    Hash hash;
    hash << data;
    return hash.hash();
}

std::vector<char> Hash::sha256(const std::string & str)
{
    Hash hash;
    hash << str;
    return hash.hash();
}

Hash::Hash()
: m_context(0)
, m_hashLength(0)
{
    // Initialize gcrypt context
    gcry_error_t error = gcry_md_open(&m_context, GCRY_MD_SHA256, 0);
    if (error != 0) handleError(error);

    // Get hash length
    m_hashLength = gcry_md_get_algo_dlen(GCRY_MD_SHA256);
}

Hash::~Hash()
{
    // Close gcrypt context
    gcry_md_close(m_context);
}

size_t Hash::hashLength() const
{
    // Return length of hash code
    return m_hashLength;
}

void Hash::add(const char * buffer, size_t size)
{
    // Check parameters
    if (!buffer || size == 0) {
        return;
    }

    // Process data
    gcry_md_write(m_context, buffer, size);
}

Hash & Hash::operator <<(const std::vector<char> & data)
{
    // Process data from vector
    add(data.data(), data.size());
    return *this;
}

Hash & Hash::operator <<(const std::string & str)
{
    // Process data from string
    add(str.c_str(), str.size());
    return *this;
}

std::vector<char> Hash::hash() const
{
    // Get result buffer
    const char * result = reinterpret_cast<const char *>(gcry_md_read(m_context, 0));

    // Convert into vector
    std::vector<char> hash(m_hashLength, 0);
    for (size_t i=0; i<m_hashLength; i++) {
        hash[i] = result[i];
    }

    // Return hash result
    return hash;
}


} // namespace keepass_cpp
