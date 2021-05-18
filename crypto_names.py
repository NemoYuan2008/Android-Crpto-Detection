import re

crypto_names = ['sm2', 'sm3', 'sm4', 'sms4']
regex_base64 = re.compile(r'^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$')


def match_crypto_name(s: str, exclude_cert=False):
    """ Check if s contains a crypto name in crypto_names case-insensitively.
        Return the crypto name that matches, return None if no names match.
    """
    if exclude_cert and (len(s) >= 300 or 'CERTIFICATE' in s):  # Exclude certificate strings. 
        return None
    
    s_fold = s.casefold()
    if 'm3u8' in s_fold or 'lambda' in s_fold:
        return None
    if s.isascii() and regex_base64.match(s) and s.endswith('=') and 'sm4=' not in s_fold:
        return None

    for word in crypto_names:
        if word in s_fold:
            return word
