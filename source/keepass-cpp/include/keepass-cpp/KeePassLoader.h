#pragma once


#include <vector>

#include <keepass-cpp/Random.h>


namespace pugi
{
    class xml_document;
    class xml_node;
}


namespace keepass_cpp
{


/**
*  @brief
*    Loader for KeePass2 database files
*/
class KEEPASS_CPP_API KeePassLoader
{
public:
    /**
    *  @brief
    *    Constructor
    */
    KeePassLoader();

    /**
    *  @brief
    *    Destructor
    */
    virtual ~KeePassLoader();

    /**
    *  @brief
    *    Load KeePass database
    *
    *  @param[in] filename
    *    Filename
    *  @param[in] password
    *    Master password
    */
    void load(const std::string & filename, const std::string & password);

protected:
    /**
    *  @brief
    *    Load keepass data format from stream
    *
    *  @param[in] in
    *    Input stream
    */
    void readFile(std::istream & in);

    /**
    *  @brief
    *    Transform key
    *
    *  @param[in] key
    *    Key
    *  @param[in] seed
    *    Encryption seed
    *  @param[in] rounds
    *    Number of encryption rounds
    *
    *  @return
    *    transformed key
    */
    std::vector<char> transformKey(const std::vector<char> & key, const std::vector<char> & seed, uint64_t rounds) const;

    // XML parsing functions
    void parseDocument(const pugi::xml_document & document) const;
    void parseKeePassFile(const pugi::xml_node & rootNode) const;
    void parseMeta(const pugi::xml_node & meta) const;
    void parseRoot(const pugi::xml_node & root) const;
    void parseGroup(const pugi::xml_node & group, const std::string & indent = "") const;
    void parseEntry(const pugi::xml_node & entry, const std::string & indent = "") const;
    void parseHistory(const pugi::xml_node & entry) const;
    std::pair<std::string, std::string> parseString(const pugi::xml_node & string) const;

protected:
    Random m_random;
};


} // namespace keepass_cpp
