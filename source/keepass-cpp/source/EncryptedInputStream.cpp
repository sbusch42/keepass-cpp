#include <keepass-cpp/EncryptedInputStream.h>

#include <algorithm>
#include <cstring>
#include <iostream>


#ifdef max
    #undef max
#endif


namespace keepass_cpp
{


EncryptedInputStream::EncryptedInputStream(std::istream & inputStream, const std::vector<char> & key, const std::vector<char> & iv)
: EncryptedInputStream(new EncryptedInputStreamBuffer(inputStream, key, iv))
{
}

EncryptedInputStream::~EncryptedInputStream()
{
}

EncryptedInputStream::EncryptedInputStream(std::streambuf * streamBuffer)
: std::istream(streamBuffer)
, m_streamBuffer(streamBuffer)
{
}


EncryptedInputStreamBuffer::EncryptedInputStreamBuffer(std::istream & inputStream, const std::vector<char> & key, const std::vector<char> & iv, size_t bufferSize, size_t putbackSize)
: m_inputStream(inputStream)
, m_bufferSize(std::max(bufferSize, 2 * m_decrypt.blockSize()))
, m_putbackSize(std::max(putbackSize, (size_t)1))
, m_buffer(std::max(m_bufferSize, m_putbackSize) + m_putbackSize)
{
    // Initialize decryption cipher
    m_decrypt.setKey(key);
    m_decrypt.setInitializationVector(iv);

    // Initialize read buffer
    char * end = &m_buffer.front() + m_buffer.size();
    setg(end, end, end);
}

EncryptedInputStreamBuffer::~EncryptedInputStreamBuffer()
{
}

std::streambuf::int_type EncryptedInputStreamBuffer::underflow()
{
    // Check input stream
    if (!m_inputStream.good()) {
        return traits_type::eof();
    }

    // Check if the buffer is filled
    if (gptr() < egptr()) {
        // Return next byte from buffer
        return traits_type::to_int_type(*gptr());
    }

    // Prepare buffer
    char * base  = &m_buffer.front();
    char * start = base;

    if (eback() == base) {
        std::memmove(base, egptr() - m_putbackSize, m_putbackSize);
        start += m_putbackSize;
    }

    // Refill buffer by reading the next block
    std::vector<char> buf(m_decrypt.blockSize());
    m_inputStream.read(buf.data(), buf.size());
    size_t n = m_inputStream.gcount();

    // [DEBUG]
    if (start - base + m_decrypt.blockSize() > m_buffer.size()) {
        std::cout << "BUFFER OVERFLOW" << std::endl;
    }

    // Decrypt block
    m_decrypt.decrypt(start, m_decrypt.blockSize(), buf.data(), m_decrypt.blockSize());

    // Set buffer pointers
    setg(base, start, start + n);

    // Return next byte
    return traits_type::to_int_type(*gptr());
}


} // namespace keepass_cpp
