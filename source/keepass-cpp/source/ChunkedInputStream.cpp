#include <keepass-cpp/ChunkedInputStream.h>

#include <algorithm>
#include <cstring>
#include <iostream>

#include <keepass-cpp/Tools.h>
#include <keepass-cpp/Hash.h>


#ifdef max
    #undef max
#endif


namespace keepass_cpp
{


ChunkedInputStream::ChunkedInputStream(std::istream & inputStream)
: ChunkedInputStream(new ChunkedInputStreamBuffer(inputStream))
{
}

ChunkedInputStream::~ChunkedInputStream()
{
}

ChunkedInputStream::ChunkedInputStream(std::streambuf * streamBuffer)
: std::istream(streamBuffer)
, m_streamBuffer(streamBuffer)
{
}


ChunkedInputStreamBuffer::ChunkedInputStreamBuffer(std::istream & inputStream, size_t bufferSize)
: m_inputStream(inputStream)
, m_buffer(std::max(bufferSize, (size_t)1024))
, m_blockId(0)
{
    // Initialize read buffer
    char * end = &m_buffer.front() + m_buffer.size();
    setg(end, end, end);
}

ChunkedInputStreamBuffer::~ChunkedInputStreamBuffer()
{
}

std::streambuf::int_type ChunkedInputStreamBuffer::underflow()
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

    // Read block ID
    uint32_t blockId;
    m_inputStream.read(reinterpret_cast<char *>(&blockId), sizeof(blockId));

    if (m_blockId != blockId) {
        return traits_type::eof();
    }

    m_blockId++;

    // Read hash
    std::vector<char> hashData(32);
    m_inputStream.read(hashData.data(), 32);
    std::string hash = Tools::toHexString(hashData);

    // Read block size
    uint32_t size;
    m_inputStream.read(reinterpret_cast<char *>(&size), sizeof(size));

    // Resize buffer if necessary
    if (size > m_buffer.size()) {
        m_buffer.resize(size);
    }

    // Check for final block
    if (size == 0) {
        return traits_type::eof();
    }

    // Read block
    m_inputStream.read(m_buffer.data(), size);

    // Compare checksum
    std::string hashFound = Tools::toHexString(Hash::sha256(m_buffer));
    if (hashFound != hash) {
        return traits_type::eof();
    }

    // Update buffer pointers
    setg(&m_buffer.front(), &m_buffer.front(), &m_buffer.front() + m_buffer.size());

    // Return next byte
    return traits_type::to_int_type(*gptr());
}


} // namespace keepass_cpp
