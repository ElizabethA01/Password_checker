import requests
import hashlib
import sys

def request_api_data(query_char):
    #request for data from API
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    #check that the response is == [200]
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the API and try again')
    return res

def get_password_leaks_count(hashes, hash_to_check):
    #check the tail of the hashes and return the number of times it's been used
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0

def pwned_api_check(password):
    #check password if it exists in API response
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)
    
def main(args):
    #print out the results of these functions in readable format
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times... you should probably changed your password')
        else:
            print(f'{password} was NOT found. Carry on!')
    return 'done!'


if __name__ == '__main__':
    with open('password.txt') as file:
        sys.exit(main(file.read().rstrip().split()))