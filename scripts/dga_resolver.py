import ctypes, hashlib, base64, binascii, re, sys
from ctypes import wintypes
from datetime import datetime, timedelta

# Define the SYSTEMTIME structure
class SYSTEMTIME(ctypes.Structure):
    _fields_ = [
        ("wYear", wintypes.WORD),
        ("wMonth", wintypes.WORD),
        ("wDayOfWeek", wintypes.WORD),
        ("wDay", wintypes.WORD),
        ("wHour", wintypes.WORD),
        ("wMinute", wintypes.WORD),
        ("wSecond", wintypes.WORD),
        ("wMilliseconds", wintypes.WORD),
    ]

def get_mondays(year):

    # Get the first day of the year
    first_day = datetime(year, 1, 1)

    # Calculate the weekday of the first day of the year
    days_to_add = (0 - first_day.weekday() + 7) % 7
    first_monday = first_day + timedelta(days=days_to_add)

    # Generate Mondays for the rest of the year
    mondays = [first_monday + timedelta(weeks=i) for i in range(52)]

    # Check if the last Monday is part of the next year
    if mondays[-1].year > year:
        mondays.pop()

    return mondays

def get_days(year):

    # Get the first day of the year
    first_day = datetime(year, 1, 1)

    # Calculate the total number of days in the year
    if year % 4 == 0 and (year % 100 != 0 or year % 400 == 0):
        total_days = 366  # Leap year
    else:
        total_days = 365  # Non-leap year

    # Generate all days for the rest of the year
    days = [first_day + timedelta(days=i) for i in range(total_days)]

    return days

def getsystemtime(year, month, day):

    year = hex(year)[2:]
    month = hex(month)[2:]
    day_of_week = "01"  # For Monday
    day = hex(day)[2:]
    hours_minutes = "0000"
    seconds_milliseconds = "0000"

    # Ensure that each component has two characters
    year = year.zfill(4)
    month = month.zfill(2)
    day = day.zfill(2)

    # Combine hex values into a SYSTEMTIME hex string
    systemtime_hex = year + month + day_of_week + day + hours_minutes + seconds_milliseconds

    return systemtime_hex.upper()  # Convert to uppercase for consistency

def convert_systemtime_to_filetime(systemtime_hex):

    # Load the kernel32.dll library
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    # Declare the SystemTimeToFileTime function
    SystemTimeToFileTime = kernel32.SystemTimeToFileTime
    SystemTimeToFileTime.argtypes = [ctypes.POINTER(SYSTEMTIME), ctypes.POINTER(wintypes.FILETIME)]
    SystemTimeToFileTime.restype = wintypes.BOOL

    # Create a SYSTEMTIME instance and initialize it with the hex string
    systemtime = SYSTEMTIME()
    systemtime.wYear = int(systemtime_hex[0:4], 16)
    systemtime.wMonth = int(systemtime_hex[4:6], 16)
    systemtime.wDayOfWeek = int(systemtime_hex[6:8], 16)
    systemtime.wDay = int(systemtime_hex[8:10], 16)

    # Convert SYSTEMTIME to FILETIME
    filetime = wintypes.FILETIME()
    success = SystemTimeToFileTime(ctypes.byref(systemtime), ctypes.byref(filetime))

    if success:
        combined_datetime = hex((filetime.dwHighDateTime << 32) | filetime.dwLowDateTime)[2:]
        return combined_datetime
    else:
        raise WinError(ctypes.get_last_error())

def sha256_hash(hex_string):

    # Change to Little-Endian, and convert string to hex bytes
    data_bytes = binascii.unhexlify(hex_string)[::-1]
    # data_bytes = b'\x00\x36\x0A\x65'
    sha256_hash = hashlib.sha256(data_bytes).hexdigest()
    return sha256_hash

def sha512_hash(hex_string):

    sha512 = hashlib.sha512()
    sha512.update(hex_string.encode('utf-8'))
    return sha512.hexdigest()

def sha512_hash_hex(hex_string):

    data_bytes = binascii.unhexlify(hex_string)
    sha512_hash = hashlib.sha512(data_bytes).hexdigest()
    return sha512_hash

def tobase64(sha_512_sha256_and_c2, sha_512_url=""):

    string = sha_512_sha256_and_c2 + sha_512_url
    # Encode the string to base64
    # encoded_bytes = base64.b64encode(string.encode('utf-8'))
    encoded_bytes = base64.b64encode(binascii.unhexlify(string))
    # Convert the bytes to a string
    base64_string = encoded_bytes.decode('utf-8')
    return base64_string

def clean_base64(base64_string):

    # Remove "/", "+", "=", digits, and convert to lowercase
    cleaned_string = ''.join(char.lower() for char in base64_string if char.isalpha() or char.isspace())
    # Get rid of repeating characters
    cleaned_string = ''.join(char for i, char in enumerate(cleaned_string) if i == 0 or char != cleaned_string[i - 1])

    return cleaned_string

def merge(base64_final, url):

    # Look for "$" in C2url, replace "$" and next letter with the base64
    resolved_c2 = re.sub(r"\$[a-zA-Z]", base64_final, url)
    resolved_c2 = re.sub(r'\[([^\[\]]{3,})\]', '', resolved_c2)
    resolved_c2 = re.sub(r'http://', '', resolved_c2)
    resolved_c2 = re.sub(r'\.', '[.]', resolved_c2)
    resolved_c2 = re.sub(r':443/', '', resolved_c2)

    return resolved_c2

def get_time(year, month, day):

    # Gets the systemtime for each monday in years 2023 - 2024
    systemtime = getsystemtime(year, month, day)

    # Convert systemtime to Filetime
    filetime = convert_systemtime_to_filetime(systemtime)
    filetime_int = int(filetime, 16)

    # Convert to Epoch Time
    # Cut off any remainders in division
    modified_filetime_int = (filetime_int // 0x989680) + 0x49EF6F00
    modified_filetime = hex(modified_filetime_int)[2:]
    # Get the HighdateTime (year, month, day)
    epochtime = modified_filetime[-8:]

    return epochtime

def hash_routine(final_time, c2_url):

    # Make a SHA256
    sha_256 = sha256_hash(final_time)

    # Make a SHA512 from un-resolved C2 url
    sha_512_url = sha512_hash(c2_url)

    # Make a SHA512 from SHA256 and C2 string
    url_hex = c2_url.encode("utf-8").hex()
    sha_512_sha256_and_c2 = sha512_hash_hex(sha_256 + url_hex)

    # Convert sha_512_c2 + sha_512_url to Base64
    base64_string = tobase64(sha_512_sha256_and_c2, sha_512_url)
    # Only get the first 17 bytes
    base64_string = base64_string[:17]

    # Get rid of /,+,=, 0-9 (all numbers)
    # Convert to lowercase
    # Get rid of repeating characters
    base64_final = clean_base64(base64_string)

    # Sanitize and replace the base64_final and $a part of C2url
    resolved_c2 = merge(base64_final, c2_url)

    return resolved_c2

def main():
    try:
        start_year = int(sys.argv[1])
        end_year = int(sys.argv[2])
        c2_url = sys.argv[3]
        match_days = re.search(r'#(\d+)', c2_url)
    except:
        print("Usage: file.py year-start year-end unresolved-c2 <hostname-optional>")
        print("Example: file.py 2023 2024 http://www.$s.com:443/#364")
        print("Example: file.py 2023 2024 http://$s[].ocouomors.com:443/ DESKTOP-TEST")
        exit()
    hostname = ""
    domain_days = 0x64   # The days is 100 days, if it failed to get #<days>
    if match_days:
        c2_url = re.sub(r'#\d+', '', c2_url)
        domain_days = match_days.group(1)
            
    try:
        match_hostname = re.search(r'\[\]', c2_url)
        if match_hostname:
            hostname = sys.argv[4]
            # must be uppper case
            c2_url = re.sub(r'\[\]', "[" + hostname.upper() + "]", c2_url)
    except:
        print("Enter hostname for url with '[]'")
        print("Example: file.py 2023 2024 http://$s[].ocouomors.com:443/ DESKTOP-TEST")
        exit()

    while end_year:

        if hostname:
            # Obtains the date for all days in the year
            days_in_year = get_days(end_year)

            for day in days_in_year:
                # Get epochtime from every day
                epochtime = get_time(day.year, day.month, day.day)
                resolved_c2 = hash_routine(epochtime, c2_url)
                #print(resolved_c2)
                print(resolved_c2 + ", " + day.strftime("%Y-%m-%d") + ", ")

            if end_year == start_year:
                break
            end_year = end_year - 1

        else:
            # Obtains the date for all Mondays in the year
            mondays_in_year = get_mondays(int(end_year))

            for monday in mondays_in_year:
                # Get epochtime from every monday
                epochtime = get_time(monday.year, monday.month, monday.day)

                # Perform more arithmetic
                epochtime_int = int(epochtime, 16)
                modified_time_int = 0x15180 * int(domain_days) * (epochtime_int // (int(domain_days) * 0x15180))
                final_time = hex(modified_time_int)[2:]

                resolved_c2 = hash_routine(final_time, c2_url)
                print(resolved_c2 + ", " + monday.strftime("%Y-%m-%d"))

            if end_year == start_year:
                break
            end_year = end_year - 1

if __name__ == "__main__":
    main()