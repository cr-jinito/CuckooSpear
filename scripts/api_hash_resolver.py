import re, pefile, sys

def get_dll_exports(dll_path):

    api_list = []

    try:
        # Load the DLL using pefile
        pe = pefile.PE(dll_path)

        # Check if the DLL has an Export Directory
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):

            # Iterate through the export functions
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:

                # check if function name is None
                if exp.name is not None:
                    api_list.append(exp.name.decode('utf-8'))
                else:
                    api_list.append(f"Ordinal_{exp.ordinal}")
                
        if api_list:
            return api_list

    except Exception as e:
        print(f"Error loading DLL: {e}")

def api_resolver(dll_name, api_hash, hardcoded_bytes):

    _bytes = hardcoded_bytes
    api_names = []
    # replaced backslash with chr(92) to keep color syntax
    api_names = get_dll_exports("C:\\Windows\\System32" + chr(92) + dll_name)

    for api_name in api_names:

        result = process_string(api_name[1:], ord(api_name[0]))

        # Success if the XOR result is 0
        test = result ^ api_hash ^ _bytes

        if test == 0:
            return api_name

def ROR4(value, shift):
    # Perform bitwise rotation to the right by the specified shift
    return ((value & 0xFFFFFFFF) >> shift) | ((value << (32 - shift)) & 0xFFFFFFFF)

def process_string(a1, a2):

    # Iterate through each character in api name
    for char in a1:

        # Convert the character to its integer value
        char_value = ord(char)

        # Perform ROR4 on a2 and add its result
        a2 = char_value + ROR4(a2, 7)

    return a2

def main():

    try:
        dll_name = sys.argv[1]
        api_hash = int(sys.argv[2], 16)
        hardcoded_bytes = int(sys.argv[3], 16)

    except:
        print("Usage: file.py <DLL name> <API-Hash in hex> <Hardcoded_Bytes>")
        print("Example: API-Hash-Resolver.py kernel32.dll 0xBBEE613A 0x41BEBF")
        exit()

    api_name = api_resolver(dll_name, api_hash, hardcoded_bytes)
    print(api_name)

if __name__ == "__main__":
    main()
