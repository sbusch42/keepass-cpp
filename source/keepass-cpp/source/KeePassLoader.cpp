#include <keepass-cpp/KeePassLoader.h>

#include <cstdint>
#include <fstream>
#include <sstream>
#include <iostream>

#include <basen.hpp>

#include <zstr.hpp>

#include <pugixml.hpp>

#include <keepass-cpp/Tools.h>
#include <keepass-cpp/Hash.h>
#include <keepass-cpp/Encrypt.h>
#include <keepass-cpp/Decrypt.h>
#include <keepass-cpp/EncryptedInputStream.h>
#include <keepass-cpp/ChunkedInputStream.h>


namespace
{


// KeePass definitions
static const uint32_t KEEPASS_MAGIC_1                 = 0x9AA2D903;
static const uint32_t KEEPASS_MAGIC_2                 = 0xB54BFB67;
static const int      KEEPASS_HEADER_END              = 0;
static const int      KEEPASS_HEADER_COMMENT          = 1;
static const int      KEEPASS_HEADER_CIPHER_ID        = 2;
static const int      KEEPASS_HEADER_COMPRESSION      = 3;
static const int      KEEPASS_HEADER_MASTER_SEED      = 4;
static const int      KEEPASS_HEADER_TRANSFORM_SEED   = 5;
static const int      KEEPASS_HEADER_TRANSFORM_ROUNDS = 6;
static const int      KEEPASS_HEADER_ENCRYPTION_IV    = 7;
static const int      KEEPASS_HEADER_STREAM_KEY       = 8;
static const int      KEEPASS_HEADER_START_BYTES      = 9;
static const int      KEEPASS_HEADER_RANDOM_STREAM_ID = 10;

static const std::vector<unsigned char> KEEPASS_INNER_STREAM_IV = { 0xe8, 0x30, 0x09, 0x4b, 0x97, 0x20, 0x5d, 0x2a };

static const std::string KEEPASS_CIPHER_AES = "31c1f2e6bf714350be5805216afc5aff";

static const int      KEEPASS_RANDOM_ARCFOUR = 1;
static const int      KEEPASS_RANDOM_SALSA20 = 2;


}


namespace keepass_cpp
{


KeePassLoader::KeePassLoader()
{
}

KeePassLoader::~KeePassLoader()
{
}

void KeePassLoader::load(const std::string & filename, const std::string & password)
{
    // Open file
    std::ifstream f(filename, std::ifstream::in | std::ifstream::binary);

    // Read header
    uint32_t          magicNumber1      = 0; // KEEPASS_MAGIC_1
    uint32_t          magicNumber2      = 0; // KEEPASS_MAGIC_2
    uint32_t          version           = 0; // 1 or 2
    uint64_t          transformRounds   = 1; // Number of tranformation rounds for key
    uint32_t          randomStreamType  = 0; // Cipher used for random seed
    uint32_t          compression       = 0; // 0: none, 1: gzip
    std::vector<char> masterSeed;            // Master seed to derive key
    std::vector<char> transformSeed;         // Transform seed to derive key
    std::vector<char> encryptionIV;          // Initialization vector for decryption
    std::vector<char> protectedStreamKey;    // Key to initialize random stream
    std::vector<char> streamStartBytes;      // First 32 bytes of unencrypted data
    std::string       cipher;                // Cipher ID

    // File format identifier #1
    f.read(reinterpret_cast<char *>(&magicNumber1), sizeof(magicNumber1));
    if (magicNumber1 != KEEPASS_MAGIC_1) {
        std::cout << "ERROR: Invalid file format" << std::endl;
        return;
    }

    // File format identifier #2
    f.read(reinterpret_cast<char *>(&magicNumber2), sizeof(magicNumber2));
    if (magicNumber2 != KEEPASS_MAGIC_2) {
        std::cout << "ERROR: Invalid file format" << std::endl;
        return;
    }

    // File format version
    f.read(reinterpret_cast<char *>(&version), sizeof(version));
    version = version >> 16;
    if (version != 2 && version != 3) {
        std::cout << "ERROR: Unsupported file format version " << version << std::endl;
        return;
    }

    // Read header fields
    bool finished = false;
    while (!finished) {
        // Read field type
        uint8_t fieldType;
        f.read(reinterpret_cast<char *>(&fieldType), sizeof(fieldType));

        // Read field size
        uint16_t fieldSize;
        f.read(reinterpret_cast<char *>(&fieldSize), sizeof(fieldSize));

        // Read field data
        std::vector<char> field(fieldSize);
        f.read(reinterpret_cast<char *>(field.data()), fieldSize);

        // Process header field
        switch (fieldType) {
            // Read cipher ID
            case KEEPASS_HEADER_CIPHER_ID:
            {
                cipher = Tools::toHexString(field);
                break;
            }

            // Read compression type
            case KEEPASS_HEADER_COMPRESSION:
            {
                compression = *reinterpret_cast<uint32_t *>(field.data());
                break;
            }

            // Read master seed
            case KEEPASS_HEADER_MASTER_SEED:
            {
                if (fieldSize != 32) {
                    std::cout << "ERROR: Invalid size of header field" << std::endl;
                    return;
                }

                masterSeed = field;
                break;
            }

            // Read transform seed
            case KEEPASS_HEADER_TRANSFORM_SEED:
            {
                if (fieldSize != 32) {
                    std::cout << "ERROR: Invalid size of header field" << std::endl;
                    return;
                }

                transformSeed = field;
                break;
            }

            // Read number of rounds
            case KEEPASS_HEADER_TRANSFORM_ROUNDS:
            {
                transformRounds = *reinterpret_cast<uint64_t *>(field.data());
                break;
            }

            // Read encryption IV
            case KEEPASS_HEADER_ENCRYPTION_IV:
            {
                if (fieldSize != 16) {
                    std::cout << "ERROR: Invalid size of header field" << std::endl;
                    return;
                }

                encryptionIV = field;
                break;
            }

            // Read protected stream key
            case KEEPASS_HEADER_STREAM_KEY:
            {
                if (fieldSize != 32) {
                    std::cout << "ERROR: Invalid size of header field" << std::endl;
                    return;
                }

                protectedStreamKey = field;
                break;
            }

            // Read stream start bytes
            case KEEPASS_HEADER_START_BYTES:
            {
                if (fieldSize != 32) {
                    std::cout << "ERROR: Invalid size of header field" << std::endl;
                    return;
                }

                streamStartBytes = field;
                break;
            }

            // Read random stream ID
            case KEEPASS_HEADER_RANDOM_STREAM_ID:
            {
                randomStreamType = *reinterpret_cast<uint32_t *>(field.data());
                break;
            }

            // Reached end of header
            case KEEPASS_HEADER_END:
            {
                finished = true;
                break;
            }

            // Unknown field
            default:
            {
                std::cout << "ERROR: Unknown header field" << std::endl;
                return;
            }
        }
    }

    // Check header options and compatibility
    if (cipher != KEEPASS_CIPHER_AES) {
        std::cout << "Unsupported cipher" << std::endl;
        return;
    }

    if (randomStreamType != KEEPASS_RANDOM_SALSA20) {
        std::cout << "Unsupported random stream type" << std::endl;
        return;
    }

    // Get encryption key
    auto rawKey = Hash::sha256(Hash::sha256(password));
    auto transformedKey = Hash::sha256(transformKey(rawKey, transformSeed, transformRounds));
    auto key = (Hash() << masterSeed << transformedKey).hash();

    // Open decryption stream
    EncryptedInputStream cryptIn(f, key, encryptionIV);

    // Compare first 32 bytes of decrypted data
    std::vector<char> startBytes(32);
    cryptIn.read(startBytes.data(), 32);
    if (startBytes != streamStartBytes) {
        std::cout << "ERROR: Invalid file or key" << std::endl;
        return;
    }

    // Initialize random stream to decrypt passwords (and other protected data)
    m_random.setKey(Hash::sha256(protectedStreamKey));
    m_random.setInitializationVector(reinterpret_cast<const std::vector<char>&>(KEEPASS_INNER_STREAM_IV));

    // Open stream for chunked file format
    ChunkedInputStream chunkIn(cryptIn);

    // Open decompression stream
    if (compression == 1) {
        zstr::istream zIn(chunkIn);
        readFile(zIn);
    } else {
        readFile(chunkIn);
    }
}

void KeePassLoader::readFile(std::istream & in)
{
    // Parse XML document
    pugi::xml_document doc;
    doc.load(in);
    parseDocument(doc);

    // [DEBUG]
//  doc.save(std::cout);
}

std::vector<char> KeePassLoader::transformKey(const std::vector<char> & key, const std::vector<char> & seed, uint64_t rounds) const
{
    // Initialize encryption
    Encrypt encrypt;
    encrypt.setKey(seed);

    // Transform key several times
    std::vector<char> data = key;
    for (uint64_t i=0; i<rounds; i++) {
        encrypt.encrypt(data.data(), data.size());
    }

    // Return transformed key
    return data;
}

void KeePassLoader::parseDocument(const pugi::xml_document & document) const
{
    // Get root element of XML document
    auto rootNode = document.document_element();
    std::string nodeName = rootNode.name();

    // Expect <KeePassFile>
    if (rootNode.type() != pugi::node_element || nodeName != "KeePassFile") {
        std::cout << "Error parsing KeeNode XML" << std::endl;
        return;
    }

    // Parse <KeePassFile> tag
    parseKeePassFile(rootNode);
}

void KeePassLoader::parseKeePassFile(const pugi::xml_node & rootNode) const
{
    // Process child nodes
    for (pugi::xml_node node = rootNode.first_child(); node; node = node.next_sibling()) {
        std::string nodeName = node.name();

        // Parse <Meta> tag
        if (node.type() == pugi::node_element && nodeName == "Meta") {
            parseMeta(node);
        }

        // Parse <Root> tag
        if (node.type() == pugi::node_element && nodeName == "Root") {
            parseRoot(node);
        }
    }
}

void KeePassLoader::parseMeta(const pugi::xml_node &) const
{
    // [TODO]
}

void KeePassLoader::parseRoot(const pugi::xml_node & root) const
{
    // Process child nodes
    for (pugi::xml_node node = root.first_child(); node; node = node.next_sibling()) {
        std::string nodeName = node.name();

        // Parse <Group> tag
        if (node.type() == pugi::node_element && nodeName == "Group") {
            parseGroup(node);
        }
    }
}

void KeePassLoader::parseGroup(const pugi::xml_node & group, const std::string & indent) const
{
    std::string uuid;
    std::string name;
    std::string notes;

    // Process child nodes
    for (pugi::xml_node node = group.first_child(); node; node = node.next_sibling()) {
        std::string nodeName = node.name();
        if (node.type() != pugi::node_element) {
            continue;
        }

        // Parse <UUID>, <Name>, <Notes> tags
        if (nodeName == "UUID")  uuid  = node.child_value();
        if (nodeName == "Name")  name  = node.child_value();
        if (nodeName == "Notes") notes = node.child_value();
    }

    // [DEBUG]
    std::cout << indent << "GROUP '" << name << "' [" << uuid << "] (" << notes << ")" << std::endl;

    // Process sub-groups
    for (pugi::xml_node node = group.first_child(); node; node = node.next_sibling()) {
        std::string nodeName = node.name();

        // Parse <Group> tag
        if (node.type() == pugi::node_element && nodeName == "Group") {
            parseGroup(node, indent + "    ");
        }
    }

    // Process entries
    for (pugi::xml_node node = group.first_child(); node; node = node.next_sibling()) {
        std::string nodeName = node.name();

        // Parse <Entry> tag
        if (node.type() == pugi::node_element && nodeName == "Entry") {
            parseEntry(node, indent + "    ");
        }
    }
}

void KeePassLoader::parseEntry(const pugi::xml_node & entry, const std::string & indent) const
{
    std::string uuid;
    std::string title;
    std::string username;
    std::string password;
    std::string url;
    std::string notes;

    // Process child nodes
    for (pugi::xml_node node = entry.first_child(); node; node = node.next_sibling()) {
        std::string nodeName = node.name();
        if (node.type() != pugi::node_element) {
            continue;
        }

        // Parse <UUID> tag
        if (nodeName == "UUID") {
            uuid = node.child_value();
        }

        // Parse <String> tag
        else if (nodeName == "String") {
            // Get key and value
            auto pair = parseString(node);
            std::string key   = pair.first;
            std::string value = pair.second;

            // Save information
            if (key == "Title")    title = value;
            if (key == "UserName") username = value;
            if (key == "Password") password = value;
            if (key == "URL")      url = value;
            if (key == "Notes")    notes = value;
        }

        // Parse <History> tag
        else if (nodeName == "History") {
            parseHistory(node);
        }
    }

    // [DEBUG]
    std::cout << indent << "ENTRY '" << title << "' [" << uuid << "] (" << notes << ")" << std::endl;
    std::cout << indent << "- Username: " << username << std::endl;
    std::cout << indent << "- Password: " << password << std::endl;
    std::cout << indent << "- Url:      " << url << std::endl;
    std::cout << indent << "- Notes:    " << notes << std::endl;
    std::cout << std::endl;
}

void KeePassLoader::parseHistory(const pugi::xml_node & parent) const
{
    // Process child nodes
    for (pugi::xml_node node = parent.first_child(); node; node = node.next_sibling()) {
        std::string nodeName = node.name();
        if (node.type() != pugi::node_element) {
            continue;
        }

        // Parse <String> tag
        if (nodeName == "String") {
            auto pair = parseString(node);
        }

        // Process all other nodes and subtrees
        else {
            parseHistory(node);
        }
    }
}

std::pair<std::string, std::string> KeePassLoader::parseString(const pugi::xml_node & string) const
{
    std::string key;
    std::string value;

    // Process child nodes
    for (pugi::xml_node node = string.first_child(); node; node = node.next_sibling()) {
        std::string nodeName = node.name();
        if (node.type() != pugi::node_element) {
            continue;
        }

        // Read key
        if (nodeName == "Key") {
            key = node.child_value();
        }

        // Read value
        else if (nodeName == "Value") {
            // Get value
            value = node.child_value();

            // Check if value is protected
            std::string protectedValue = node.attribute("Protected").value();
            if (protectedValue == "True" && value != "") {
                // Decode string from Base64
                std::vector<char> data;
                bn::decode_b64(value.begin(), value.end(), back_inserter(data));

                // Decrypt value
                m_random.transform(data.data(), data.size());

                // Convert value to string
                std::string clean(data.data(), data.size());
                value = clean;
            }
        }
    }

    // Return key/value pair
    std::pair<std::string, std::string> pair;
    pair.first  = key;
    pair.second = value;
    return pair;
}


} // namespace keepass_cpp
