# XBE-Parser
A basic tool for bulk exporting Xbox Executable (XBE) file header and cert info.

# Usage
1. Compile with C++17 or later to obtain executable file.
2. Place .exe in folder containing XBEs (it will also recurse and find XBEs in subfolders).
3. Run .exe. 

A tab-separated CSV file will be generated in the directory the .exe was run from. Import into Excel (or other program) using tabs as separators.
