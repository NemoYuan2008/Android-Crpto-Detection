import sys
import operator
from androguard.misc import AnalyzeAPK

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


class AnalyseApkCrypto:
    """ Analyse an APK.

        Accessible attributes:
            app_name: str
                App name of the APK.

            package_name: str
                Package name of the APK.

            classes_with_crypto: dict
                The keys are crypto names, the values are dictionaries,
                whose keys are class names, values are a list of method names in the class.
                Only classes or methods that contains crypto names are included.
    """
    def __init__(self, filename):
        self.a, self.d, self.dx = AnalyzeAPK(filename)
        # self.classes_and_methods = self._get_classes_methods()
        self.classes_with_crypto = {}
        for name in crypto_names:
            self.classes_with_crypto[name] = {}
        self._get_classes_with_crypto()
        self._get_classes_with_crypto_strings()

    @property
    def app_name(self):
        return self.a.get_app_name()

    @property
    def package_name(self):
        return self.a.get_package()
    
    def _get_classes_methods(self):
        results = {}
        classes = self.dx.get_classes()
        for c in classes:
            results[c.name] = []
            for meth in c.get_methods():
                results[c.name].append(meth.name)
        return results

    def _get_classes_with_crypto(self):
        classes = self.dx.get_classes()
        for c in classes:
            crypto_name = match_crypto_name(c.name)
            if crypto_name:     # Class name matches a crypto name
                # All method names of the class are included
                self.classes_with_crypto[crypto_name][c.name] = list(map(operator.attrgetter('name'), c.get_methods()))
            else:   # Class name doesn't match
                for meth in c.get_methods():
                    crypto_name = match_crypto_name(meth.name)
                    if crypto_name is None:
                        continue
                    # Class name doesn't match but a method does
                    if c.name not in self.classes_with_crypto[crypto_name]: 
                        self.classes_with_crypto[crypto_name][c.name] = []
                    self.classes_with_crypto[crypto_name][c.name].append(meth.name)

    def _get_classes_with_crypto_strings(self):
        for s in self.dx.get_strings():
            s_value = s.get_orig_value()
            crypto_name = match_crypto_name(s_value, exclude_cert=True)
            if crypto_name is None:
                continue
            for c, meth in s.get_xref_from():
                if c.name not in self.classes_with_crypto[crypto_name]:
                    self.classes_with_crypto[crypto_name][c.name] = []
                self.classes_with_crypto[crypto_name][c.name].append((meth.name, s_value))


if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.stderr.write('Need an argument\n')
        sys.exit(1)
    # test case: ~/Desktop/apk/boc.apk
    ana = AnalyseApkCrypto(sys.argv[1])
    print(ana.app_name)
    print(ana.package_name)
    print(ana.classes_with_crypto)
