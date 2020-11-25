# nongrata
Allows you to encrypt and decrypt files using XOR operation

nongrata project - version 1.3

# General info
- Designed to run in Linux
- Doesn't have interface, so you need to run it in terminal
- Algorithm of encryption/decryption is XOR operation

# How to use:
- Write **./nongrata -h** in terminal to get info about program and how to use it

## Some abbreviation:
- fun_al() -> **al** means *"allocate"* 
        
## Some troubles:
- When I use function fseek() I don't check current position in file.
*You need to check this parameter to avoid some troubles with file's data.*
        
- I have function get_file_length() which returns size of file. When I call
function get_file_lenght() I have already opened file. In get_file_length() 
I use function stat() to get the size of file. 


## Some future changes:
- Ask key twice and compare them for correctness.

- When I input file from command line - may be check if files are exist in
this folder ? If there are no such files - don't ask to input key for 
encryption/decryption.

- Use not only one path by encryption/decryption.

- Delete encrypted/decrypted files if user wants it (aks a question).

- Delete all information about file: cache, file data, RAM and so on.

- Add user interface

- Need to write new algorithm, because current is very weak.

- Add network/usb versions
     
