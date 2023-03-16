#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <filesystem>
#include <iomanip>

using namespace std;

typedef signed int     sint;
typedef unsigned int   uint;
typedef char           int08;
typedef short          int16;
typedef long           int32;
typedef unsigned char  uint08;
typedef unsigned short uint16;
typedef unsigned long  uint32;
typedef signed char    sint08;
typedef signed short   sint16;
typedef signed long    sint32;

#pragma pack(1)
struct XbeFileStructure
{
    struct XbeHeader
    {
        uint32 m_magic;                         // magic number [should be "XBEH"]
        uint08 m_digsig[256];                   // digital signature
        uint32 m_base;                          // base address
        uint32 m_sizeof_headers;                // size of headers
        uint32 m_sizeof_image;                  // size of image
        uint32 m_sizeof_image_header;           // size of image header
        uint32 m_timedate;                      // timedate stamp
        uint32 m_certificate_addr;              // certificate address
        uint32 m_sections;                      // number of sections
        uint32 m_section_headers_addr;          // section headers address

        union
        {
            uint32 init_flags_packed;

            struct init_flags
            {
                uint m_mount_utility_drive : 1;  // mount utility drive flag
                uint m_format_utility_drive : 1;  // format utility drive flag
                uint m_limit_64mb : 1;  // limit development kit run time memory to 64mb flag
                uint m_dont_setup_harddisk : 1;  // don't setup hard disk flag
                uint m_unused : 4;  // unused (or unknown)
                uint m_unused_b1 : 8;  // unused (or unknown)
                uint m_unused_b2 : 8;  // unused (or unknown)
                uint m_unused_b3 : 8;  // unused (or unknown)
            }m_init_flags_bitfield;
        } m_init_flags;

        uint32 m_entry;                         // entry point address
        uint32 m_tls_addr;                      // thread local storage directory address
        uint32 m_pe_stack_commit;               // size of stack commit
        uint32 m_pe_heap_reserve;               // size of heap reserve
        uint32 m_pe_heap_commit;                // size of heap commit
        uint32 m_pe_base_addr;                  // original base address
        uint32 m_pe_sizeof_image;               // size of original image
        uint32 m_pe_checksum;                   // original checksum
        uint32 m_pe_timedate;                   // original timedate stamp
        uint32 m_debug_pathname_addr;           // debug pathname address
        uint32 m_debug_filename_addr;           // debug filename address
        uint32 m_debug_unicode_filename_addr;   // debug unicode filename address
        uint32 m_kernel_image_thunk_addr;       // kernel image thunk address
        uint32 m_nonkernel_import_dir_addr;     // non kernel import directory address
        uint32 m_library_versions;              // number of library versions
        uint32 m_library_versions_addr;         // library versions address
        uint32 m_kernel_library_version_addr;   // kernel library version address
        uint32 m_xapi_library_version_addr;     // xapi library version address
        uint32 m_logo_bitmap_addr;              // logo bitmap address
        uint32 m_logo_bitmap_size;              // logo bitmap size
        char m_debug_pathname[256];             // extra - debug pathname
        char m_debug_filename[256];             // extra - debug filename
    }
    m_header;

    struct certificate
    {
        uint32 m_size;                          // size of certificate
        uint32 m_timedate;                      // timedate stamp
        uint32 m_titleid;                       // title id
        uint16 m_title_name[40];                // title name (unicode)
        uint32 m_alt_title_id[0x10];            // alternate title ids
        uint32 m_allowed_media;                 // allowed media types
        uint32 m_game_region;                   // game region
        uint32 m_game_ratings;                  // game ratings
        uint32 m_disk_number;                   // disk number
        uint32 m_version;                       // version
        uint08 m_lan_key[16];                   // lan key
        uint08 m_sig_key[16];                   // signature key
        uint08 m_title_alt_sig_key[16][16];     // alternate signature keys
    }
    m_certificate;
}
m_xbeFile;

struct section_header
{
    struct flags                            // flags
    {
        uint m_writable : 1;    // writable flag
        uint m_preload : 1;    // preload flag
        uint m_executable : 1;    // executable flag
        uint m_inserted_file : 1;    // inserted file flag
        uint m_head_page_ro : 1;    // head page read only flag
        uint m_tail_page_ro : 1;    // tail page read only flag
        uint m_unused_a1 : 1;    // unused (or unknown)
        uint m_unused_a2 : 1;    // unused (or unknown)
        uint m_unused_b1 : 8;    // unused (or unknown)
        uint m_unused_b2 : 8;    // unused (or unknown)
        uint m_unused_b3 : 8;    // unused (or unknown)
    }m_flags;
    uint32  m_virtual_addr;                  // virtual address
    uint32  m_virtual_size;                  // virtual size
    uint32  m_raw_addr;                      // file offset to raw data
    uint32  m_sizeof_raw;                    // size of raw data
    uint32  m_section_name_addr;             // section name addr
    uint32  m_section_reference_count;       // section reference count
    uint16* m_head_shared_ref_count_addr;    // head shared page reference count address
    uint16* m_tail_shared_ref_count_addr;    // tail shared page reference count address
    uint08  m_section_digest[20];            // section digest
}
*m_section_header;

struct library_version
{
    char   m_name[8];                       // library name
    uint16 m_major_version;                 // major version
    uint16 m_minor_version;                 // minor version
    uint16 m_build_version;                 // build version
    struct flags                            // flags
    {
        uint16 m_qfe_version : 13;   // QFE Version
        uint16 m_approved : 2;    // Approved? (0:no, 1:possibly, 2:yes)
        uint16 m_debug_build : 1;    // Is this a debug build?
    }m_flags;
}
*m_library_version, * m_kernel_version, * m_xapi_version;

struct tls                                  // thread local storage
{
    uint32 m_data_start_addr;               // raw start address
    uint32 m_data_end_addr;                 // raw end address
    uint32 m_tls_index_addr;                // tls index  address
    uint32 m_tls_callback_addr;             // tls callback address
    uint32 m_sizeof_zero_fill;              // size of zero fill
    uint32 m_characteristics;               // characteristics
}
*m_tls;

void readXbeHeader(wstring filename, XbeFileStructure& xbeFileStructure) {
    
    std::ifstream file(filename, std::ios::binary);

    if (!file.is_open()) {
        wcout << "Error: cannot open file " << filename << endl;
        return;
    }
    file.seekg(0, ios::beg);

    // Read the fields from the XBE header into the header struct
    file.read(reinterpret_cast<char*>(&xbeFileStructure.m_header.m_magic), sizeof(xbeFileStructure.m_header.m_magic));
    file.read(reinterpret_cast<char*>(&xbeFileStructure.m_header.m_digsig), sizeof(xbeFileStructure.m_header.m_digsig));
    file.read(reinterpret_cast<char*>(&xbeFileStructure.m_header.m_base), sizeof(xbeFileStructure.m_header.m_base));
    file.read(reinterpret_cast<char*>(&xbeFileStructure.m_header.m_sizeof_headers), sizeof(xbeFileStructure.m_header.m_sizeof_headers));
    file.read(reinterpret_cast<char*>(&xbeFileStructure.m_header.m_sizeof_image), sizeof(xbeFileStructure.m_header.m_sizeof_image));
    file.read(reinterpret_cast<char*>(&xbeFileStructure.m_header.m_sizeof_image_header), sizeof(xbeFileStructure.m_header.m_sizeof_image_header));
    file.read(reinterpret_cast<char*>(&xbeFileStructure.m_header.m_timedate), sizeof(xbeFileStructure.m_header.m_timedate));
    file.read(reinterpret_cast<char*>(&xbeFileStructure.m_header.m_certificate_addr), sizeof(xbeFileStructure.m_header.m_certificate_addr));
    file.read(reinterpret_cast<char*>(&xbeFileStructure.m_header.m_sections), sizeof(xbeFileStructure.m_header.m_sections));
    file.read(reinterpret_cast<char*>(&xbeFileStructure.m_header.m_section_headers_addr), sizeof(xbeFileStructure.m_header.m_section_headers_addr));
    file.read(reinterpret_cast<char*>(&xbeFileStructure.m_header.m_init_flags), sizeof(xbeFileStructure.m_header.m_init_flags));
    file.read(reinterpret_cast<char*>(&xbeFileStructure.m_header.m_entry), sizeof(xbeFileStructure.m_header.m_entry));
    file.read(reinterpret_cast<char*>(&xbeFileStructure.m_header.m_tls_addr), sizeof(xbeFileStructure.m_header.m_tls_addr));
    file.read(reinterpret_cast<char*>(&xbeFileStructure.m_header.m_pe_stack_commit), sizeof(xbeFileStructure.m_header.m_pe_stack_commit));
    file.read(reinterpret_cast<char*>(&xbeFileStructure.m_header.m_pe_heap_reserve), sizeof(xbeFileStructure.m_header.m_pe_heap_reserve));
    file.read(reinterpret_cast<char*>(&xbeFileStructure.m_header.m_pe_heap_commit), sizeof(xbeFileStructure.m_header.m_pe_heap_commit));
    file.read(reinterpret_cast<char*>(&xbeFileStructure.m_header.m_pe_base_addr), sizeof(xbeFileStructure.m_header.m_pe_base_addr));
    file.read(reinterpret_cast<char*>(&xbeFileStructure.m_header.m_pe_sizeof_image), sizeof(xbeFileStructure.m_header.m_pe_sizeof_image));
    file.read(reinterpret_cast<char*>(&xbeFileStructure.m_header.m_pe_checksum), sizeof(xbeFileStructure.m_header.m_pe_checksum));
    file.read(reinterpret_cast<char*>(&xbeFileStructure.m_header.m_pe_timedate), sizeof(xbeFileStructure.m_header.m_pe_timedate));
    file.read(reinterpret_cast<char*>(&xbeFileStructure.m_header.m_debug_pathname_addr), sizeof(xbeFileStructure.m_header.m_debug_pathname_addr));
    file.read(reinterpret_cast<char*>(&xbeFileStructure.m_header.m_debug_filename_addr), sizeof(xbeFileStructure.m_header.m_debug_filename_addr));
    file.read(reinterpret_cast<char*>(&xbeFileStructure.m_header.m_debug_unicode_filename_addr), sizeof(xbeFileStructure.m_header.m_debug_unicode_filename_addr));
    file.read(reinterpret_cast<char*>(&xbeFileStructure.m_header.m_kernel_image_thunk_addr), sizeof(xbeFileStructure.m_header.m_kernel_image_thunk_addr));
    file.read(reinterpret_cast<char*>(&xbeFileStructure.m_header.m_nonkernel_import_dir_addr), sizeof(xbeFileStructure.m_header.m_nonkernel_import_dir_addr));
    file.read(reinterpret_cast<char*>(&xbeFileStructure.m_header.m_library_versions), sizeof(xbeFileStructure.m_header.m_library_versions));
    file.read(reinterpret_cast<char*>(&xbeFileStructure.m_header.m_library_versions_addr), sizeof(xbeFileStructure.m_header.m_library_versions_addr));
    file.read(reinterpret_cast<char*>(&xbeFileStructure.m_header.m_kernel_library_version_addr), sizeof(xbeFileStructure.m_header.m_kernel_library_version_addr));
    file.read(reinterpret_cast<char*>(&xbeFileStructure.m_header.m_xapi_library_version_addr), sizeof(xbeFileStructure.m_header.m_xapi_library_version_addr));
    file.read(reinterpret_cast<char*>(&xbeFileStructure.m_header.m_logo_bitmap_addr), sizeof(xbeFileStructure.m_header.m_logo_bitmap_addr));
    file.read(reinterpret_cast<char*>(&xbeFileStructure.m_header.m_logo_bitmap_size), sizeof(xbeFileStructure.m_header.m_logo_bitmap_size));

    // Certificate struct
    file.seekg(xbeFileStructure.m_header.m_certificate_addr - xbeFileStructure.m_header.m_base);
     
    file.read(reinterpret_cast<char*>(&xbeFileStructure.m_certificate.m_size), sizeof(xbeFileStructure.m_certificate.m_size));
    file.read(reinterpret_cast<char*>(&xbeFileStructure.m_certificate.m_timedate), sizeof(xbeFileStructure.m_certificate.m_timedate));
    file.read(reinterpret_cast<char*>(&xbeFileStructure.m_certificate.m_titleid), sizeof(xbeFileStructure.m_certificate.m_titleid));
    file.read(reinterpret_cast<char*>(&xbeFileStructure.m_certificate.m_title_name), sizeof(xbeFileStructure.m_certificate.m_title_name));

    for (int i = 0; i <= 15; i++) {
        file.read(reinterpret_cast<char*>(&xbeFileStructure.m_certificate.m_alt_title_id[i]), sizeof(xbeFileStructure.m_certificate.m_alt_title_id[i]));
    }

    file.read(reinterpret_cast<char*>(&xbeFileStructure.m_certificate.m_allowed_media), sizeof(xbeFileStructure.m_certificate.m_allowed_media));
    file.read(reinterpret_cast<char*>(&xbeFileStructure.m_certificate.m_game_region), sizeof(xbeFileStructure.m_certificate.m_game_region));
    file.read(reinterpret_cast<char*>(&xbeFileStructure.m_certificate.m_game_ratings), sizeof(xbeFileStructure.m_certificate.m_game_ratings));
    file.read(reinterpret_cast<char*>(&xbeFileStructure.m_certificate.m_disk_number), sizeof(xbeFileStructure.m_certificate.m_disk_number));
    file.read(reinterpret_cast<char*>(&xbeFileStructure.m_certificate.m_version), sizeof(xbeFileStructure.m_certificate.m_version));
    file.read(reinterpret_cast<char*>(&xbeFileStructure.m_certificate.m_lan_key), sizeof(xbeFileStructure.m_certificate.m_lan_key));
    file.read(reinterpret_cast<char*>(&xbeFileStructure.m_certificate.m_sig_key), sizeof(xbeFileStructure.m_certificate.m_sig_key));

    for (int i = 0; i <= 15; i++) {
         file.read(reinterpret_cast<char*>(&xbeFileStructure.m_certificate.m_title_alt_sig_key[i]), sizeof(xbeFileStructure.m_certificate.m_title_alt_sig_key[i]));
    }

    //////////// Extra info ////////////
    
    // Debug Pathname
    file.seekg(xbeFileStructure.m_header.m_debug_pathname_addr - xbeFileStructure.m_header.m_base);
    char debugPathname[256];
    file.getline(debugPathname, 256, '\0');
    strcpy_s(xbeFileStructure.m_header.m_debug_pathname, sizeof(xbeFileStructure.m_header.m_debug_pathname), debugPathname);

    // Debug Filename
    file.seekg(xbeFileStructure.m_header.m_debug_filename_addr - xbeFileStructure.m_header.m_base);
    char debugFilename[256];
    file.getline(debugFilename, 256, '\0');
    strcpy_s(xbeFileStructure.m_header.m_debug_filename, sizeof(xbeFileStructure.m_header.m_debug_filename), debugFilename);

    file.close();
}

uint16 changeEndianness(uint16 val) {
    return (val << 8) |
        ((val >> 8) & 0x00ff);
}

uint32 changeEndianness(uint32 val) {
    return (val << 24) |
        ((val << 8) & 0x00ff0000) |
        ((val >> 8) & 0x0000ff00) |
        ((val >> 24) & 0x000000ff);
}

void outputCsv(string inputFilepath, const std::vector<XbeFileStructure>& xbeFileStructures) {
    // Output CSV headers
    string filename = "Extracted_XBE_Info.csv";

    std::wofstream outputFile(inputFilepath + filename, ios::binary);
    const uint16_t bom = 0xFEFF;
    //outputFile.write(reinterpret_cast<const char*>(&bom), sizeof(bom));    // optional Byte order mark
    outputFile << "Title Name	Magic Number	Signature	Base Address	Size of Headers	Size of Image	Size of Image Header	Time Date Stamp	Certificate Address	Number of Sections	Section Headers Address	Init Flags	Entrypoint	TLS Address	Stack Commit Size	Heap Reserve Size	Heap Commit Size	PE Base Address	PE Image Size	PE Checksum	PE Timestamp	Debug Pathname Address	Debug Filename Address	Debug Unicode Filename Address	Full Debug Path	Kernel Image Thunk Address	Non-Kernel Import Directory Address	Library Versions Count	Library Versions Address	Kernel Library Version Address	XAPI Library Version Address	Logo Bitmap Address	Logo Bitmap Size	Certificate Size	Certificate Timestamp	Certificate TitleID	Certificate Alternate Title ID 0	Certificate Alternate Title ID 1	Certificate Alternate Title ID 2	Certificate Alternate Title ID 3	Certificate Alternate Title ID 4	Certificate Alternate Title ID 5	Certificate Alternate Title ID 6	Certificate Alternate Title ID 7	Certificate Alternate Title ID 8	Certificate Alternate Title ID 9	Certificate Alternate Title ID 10	Certificate Alternate Title ID 11	Certificate Alternate Title ID 12	Certificate Alternate Title ID 13	Certificate Alternate Title ID 14	Allowed Media Types	Game Region	Game Ratings	Disk Number	Version	LAN Key	Signature Key	Alternate Signature Key 0	Alternate Signature Key 1	Alternate Signature Key 2	Alternate Signature Key 3	Alternate Signature Key 4	Alternate Signature Key 5	Alternate Signature Key 6	Alternate Signature Key 7	Alternate Signature Key 8	Alternate Signature Key 9	Alternate Signature Key 10	Alternate Signature Key 11	Alternate Signature Key 12	Alternate Signature Key 13	Alternate Signature Key 14	Alternate Signature Key 15 \n";
    outputFile.close();

    for (const auto& xbeFileStructure : xbeFileStructures) {
        
        // Unicode handling to get Title Name
        std::wstring titleString;
        for (int i = 0; i < 40; i++) {
            if (changeEndianness(xbeFileStructure.m_certificate.m_title_name[i]) != '\0') {
                titleString += changeEndianness(xbeFileStructure.m_certificate.m_title_name[i]);
            }
        }

        std::ofstream outputFileNarrow(inputFilepath + filename, ios::app | ios::binary);
        outputFileNarrow.write(reinterpret_cast<const char*>(titleString.data()), titleString.size() * sizeof(wchar_t));
        outputFileNarrow.close();

        // Get Title ID
        uint32_t m_titleid = xbeFileStructure.m_certificate.m_titleid;
        uint16_t first_two_bytes = (m_titleid & 0xFFFF0000) >> 16;
        std::string titleid_letters_string = std::string(1, static_cast<char>(first_two_bytes >> 8)) + std::string(1, static_cast<char>(first_two_bytes & 0xFF));
        std::wstring titleid_letters_wstring(titleid_letters_string.begin(), titleid_letters_string.end());
        uint32_t titleid_numbers = m_titleid & 0x0000FFFF;
        
        // Alternate Title IDs
        uint32_t m_alt_title_id[0x10];
        uint16_t alt_first_two_bytes[0x10];
        std::wstring alt_titleid_letters_wstring[0x10];
        uint32_t alt_titleid_numbers[0x10];
        for (int i = 0; i < 15; i++) {
            m_alt_title_id[i] = xbeFileStructure.m_certificate.m_alt_title_id[i];
            alt_first_two_bytes[i] = (m_titleid & 0xFFFF0000) >> 16;
            std::string alt_titleid_letters_string = std::string(1, static_cast<char>(alt_first_two_bytes[i] >> 8)) + std::string(1, static_cast<char>(alt_first_two_bytes[i] & 0xFF));
            alt_titleid_letters_wstring[i] = std::wstring(alt_titleid_letters_string.begin(), alt_titleid_letters_string.end());
            alt_titleid_numbers[i] = m_alt_title_id[i] & 0x0000FFFF;
        }

        std::wofstream outputFile(inputFilepath + filename, ios::app | ios::binary);
        outputFile << '\t' << std::hex << changeEndianness(xbeFileStructure.m_header.m_magic) << '\t';
        
        for (int i = 0; i <= 255; i++) {
            outputFile << std::hex << xbeFileStructure.m_header.m_digsig[i];
        }

        outputFile << '\t'
            << "0x" << setfill(L'0') << setw(8) << right << std::hex << xbeFileStructure.m_header.m_base << '\t'
            << std::dec << xbeFileStructure.m_header.m_sizeof_headers << '\t'
            << xbeFileStructure.m_header.m_sizeof_image << '\t'
            << xbeFileStructure.m_header.m_sizeof_image_header << '\t'
            << std::hex << xbeFileStructure.m_header.m_timedate << '\t'
            << "0x" << setfill(L'0') << setw(8) << right << std::hex << xbeFileStructure.m_header.m_certificate_addr << '\t'
            << xbeFileStructure.m_header.m_sections << '\t'
            << "0x" << setfill(L'0') << setw(8) << right << std::hex << xbeFileStructure.m_header.m_section_headers_addr << '\t'
            << "0x" << setfill(L'0') << setw(8) << right << std::hex << xbeFileStructure.m_header.m_init_flags.init_flags_packed << '\t'
            << "0x" << setfill(L'0') << setw(8) << right << std::hex << (xbeFileStructure.m_header.m_entry ^ 0xA8FC57AB) << '\t' //XOR with retail key
            << "0x" << setfill(L'0') << setw(8) << right << std::hex << xbeFileStructure.m_header.m_tls_addr << '\t'
            << "0x" << setfill(L'0') << setw(8) << right << xbeFileStructure.m_header.m_pe_stack_commit << '\t'
            << "0x" << setfill(L'0') << setw(8) << right << xbeFileStructure.m_header.m_pe_heap_reserve << '\t'
            << "0x" << setfill(L'0') << setw(8) << right << xbeFileStructure.m_header.m_pe_heap_commit << '\t'
            << "0x" << setfill(L'0') << setw(8) << right << std::hex << xbeFileStructure.m_header.m_pe_base_addr << '\t'
            << "0x" << setfill(L'0') << setw(8) << right << xbeFileStructure.m_header.m_pe_sizeof_image << '\t'
            << "0x" << setfill(L'0') << setw(8) << right << xbeFileStructure.m_header.m_pe_checksum << '\t'
            << xbeFileStructure.m_header.m_pe_timedate << '\t'
            << "0x" << setfill(L'0') << setw(8) << right << std::hex << xbeFileStructure.m_header.m_debug_pathname_addr << '\t'
            << "0x" << setfill(L'0') << setw(8) << right << std::hex << xbeFileStructure.m_header.m_debug_filename_addr << '\t'
            << "0x" << setfill(L'0') << setw(8) << right << std::hex << xbeFileStructure.m_header.m_debug_unicode_filename_addr << '\t'
            << xbeFileStructure.m_header.m_debug_pathname << '\t'
            << "0x" << setfill(L'0') << setw(8) << right << std::hex << (xbeFileStructure.m_header.m_kernel_image_thunk_addr ^ 0x5B6D40B6) << '\t' //XOR with retail key
            << "0x" << setfill(L'0') << setw(8) << right << std::hex << std::hex << xbeFileStructure.m_header.m_nonkernel_import_dir_addr << '\t'
            << xbeFileStructure.m_header.m_library_versions << '\t'
            << "0x" << setfill(L'0') << setw(8) << right << std::hex << std::hex << xbeFileStructure.m_header.m_library_versions_addr << '\t'
            << "0x" << setfill(L'0') << setw(8) << right << std::hex << std::hex << xbeFileStructure.m_header.m_kernel_library_version_addr << '\t'
            << "0x" << setfill(L'0') << setw(8) << right << std::hex << std::hex << xbeFileStructure.m_header.m_xapi_library_version_addr << '\t'
            << std::hex << xbeFileStructure.m_header.m_logo_bitmap_addr << '\t'
            << xbeFileStructure.m_header.m_logo_bitmap_size << '\t'
            
            // Certificate
            << xbeFileStructure.m_certificate.m_size << '\t'
            << xbeFileStructure.m_certificate.m_timedate << '\t'
            << titleid_letters_wstring << "-" << setfill(L'0') << setw(4) << right << titleid_numbers << '\t';
            
            for (int i = 0; i < 15; i++) {
                outputFile << xbeFileStructure.m_certificate.m_alt_title_id[i] << '\t';
            }

            outputFile << setfill(L'0') << setw(8) << right << xbeFileStructure.m_certificate.m_allowed_media << '\t'
                << xbeFileStructure.m_certificate.m_game_region << '\t'
                << xbeFileStructure.m_certificate.m_game_ratings << '\t'
                << xbeFileStructure.m_certificate.m_disk_number << '\t'
                << xbeFileStructure.m_certificate.m_version << '\t';

            if (static_cast<int08>(xbeFileStructure.m_certificate.m_lan_key[0] == 'T')) {
                //Debug keys
                for (int i = 0; i <= 15; i++) {
                    outputFile << static_cast<int08>(xbeFileStructure.m_certificate.m_lan_key[i]);
                }
                outputFile << '\t';

                for (int i = 0; i <= 15; i++) {
                    outputFile << static_cast<int08>(xbeFileStructure.m_certificate.m_sig_key[i]);
                }

                outputFile << '\t';

                for (int i = 0; i <= 15; i++) {
                    for (int j = 0; j < 15; j++) {
                        outputFile << static_cast<int08>(xbeFileStructure.m_certificate.m_title_alt_sig_key[i][j]);
                    }
                    outputFile << '\t';
                }
            }
            else {
                //Retail keys
                for (int i = 0; i <= 15; i++) {
                    outputFile << xbeFileStructure.m_certificate.m_lan_key[i];
                }
                
                outputFile << '\t';

                for (int i = 0; i <= 15; i++) {
                    outputFile << xbeFileStructure.m_certificate.m_sig_key[i];
                }
                
                outputFile << '\t';

                for (int i = 0; i <= 15; i++) {
                    for (int j = 0; j < 15; j++) {
                        outputFile << xbeFileStructure.m_certificate.m_title_alt_sig_key[i][j];
                    }
                    outputFile << '\t';
                }
            }
            outputFile << "\n";
            outputFile.close();
            outputFile.imbue(locale("en_US.utf8"));
    }
}

void findXbeFilesRecursive(const std::filesystem::path& directory, std::vector<std::wstring>& xbeFiles) {
    for (const auto& entry : std::filesystem::directory_iterator(directory)) {
        if (entry.is_directory()) {
            findXbeFilesRecursive(entry.path(), xbeFiles);
        }
        else if (entry.is_regular_file() && entry.path().extension() == ".xbe") {
            xbeFiles.push_back(entry.path().wstring());
        }
    }
}

int main(int argc, char* argv[]) {
    // // check if there are any input arguments
    // if (argc < 2) {
    //     cout << "Usage: " << argv[0] << " <filename1.xbe> <filename2.xbe> ..." << endl;
    //     return 0;
    // }

    // Setup filepaths and locale for Unicode
    std::setlocale(LC_ALL, "en_US.utf8");
    std::filesystem::path currentPath = std::filesystem::current_path();
    std::string inputFilepath = currentPath.string() + "\\";
    std::vector<std::wstring> xbeFiles;
    //inputFilepath = "C:\\Users\\Derf\\Desktop\\XBE Parser\\"; //Debug filepath

    // Get all .xbe filenames from current directory and subfolders
    findXbeFilesRecursive(inputFilepath, xbeFiles);

    // Print all XBE files in array
    std::cout << "XBE Files in Directory:" << std::endl;
    for (auto file : xbeFiles) {
        std::wcout << file << std::endl;
    }
    std::cout << endl;

    // Create a vector of XbeHeader and certificate structs to store the headers of all the XBE files
    vector<XbeFileStructure> xbeFileStructures;

    // Read the XBE headers from each input file and store them in the headers vector
    for (auto xbeFile : xbeFiles) {
        XbeFileStructure XbeFileStructure;
        readXbeHeader(xbeFile, XbeFileStructure);
        xbeFileStructures.push_back(XbeFileStructure);;
    }

    // Output the headers in CSV format
    outputCsv(inputFilepath, xbeFileStructures);

    return 0;
}
