crypto_names = ['sm3', 'sm4', 'aes']


def match_crypto_name(s, exclude_cert=False):
    """ Check if s contains a crypto name in crypto_names case-insensitively.
        Return the crypto name that matches, return None if no names match.
    """
    if exclude_cert and 'CERTIFICATE' in s:  # Exclude certificate strings. 
        return None
    for word in crypto_names:
        if word in s.casefold():
            return word
