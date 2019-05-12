#pragma once


#include <memory>
#include <vector>
#include <streambuf>
#include <istream>

#include <keepass-cpp/keepass-cpp_api.h>


namespace keepass_cpp
{


/**
*  @brief
*    Input stream for chunked data
*/
class KEEPASS_CPP_API ChunkedInputStream : public std::istream
{
public:
    /**
    *  @brief
    *    Constructor
    *
    *  @param[in] inputStream
    *    Chunked input stream
    */
    ChunkedInputStream(std::istream & inputStream);

    /**
    *  @brief
    *    Destructor
    */
    virtual ~ChunkedInputStream();

protected:
    /**
    *  @brief
    *    Constructor
    *
    *  @param[in] sb
    *    Stream buffer
    */
    ChunkedInputStream(std::streambuf * streamBuffer);

protected:
    std::unique_ptr<std::streambuf> m_streamBuffer; ///< The associated stream buffer
};


/**
*  @brief
*    Stream buffer for reading from a chunked input stream
*/
class KEEPASS_CPP_API ChunkedInputStreamBuffer : public std::streambuf
{
public:
    /**
    *  @brief
    *    Constructor
    *
    *  @param[in] inputStream
    *    Chunked input stream
    *  @param[n] bufferSize
    *    Size of the read buffer
    *  @param[n] putbackSize
    *    Size of the putback area
    */
    ChunkedInputStreamBuffer(std::istream & inputStream, size_t bufferSize = 32 * 1024);

    /**
    *  @brief
    *    Destructor
    */
    virtual ~ChunkedInputStreamBuffer();

    // Virtual streambuf functions
    virtual std::streambuf::int_type underflow() override;

protected:
    std::istream      & m_inputStream; ///< Chunked input stream
    std::vector<char>   m_buffer;      ///< Read buffer
    uint32_t            m_blockId;     ///< Current block ID
};


} // namespace keepass_cpp
