import sys
import logging
from androguard.misc import AnalyzeAPK
from androguard.core.analysis.analysis import MethodClassAnalysis
from crypto_names import *
from analyse_elf import analyse_apk_elf
from constants import crypto_constants


logger = logging.getLogger('AndroidCryptoDetection')


class MethodInfo:
    def __init__(self, meth: MethodClassAnalysis, class_name: str):
        # self.meth = meth
        self.name = meth.name
        self.class_name = class_name
        self.strings = set()

        self.crypto_constants_results = {}
        for name, constant in crypto_constants.items():
            self.crypto_constants_results[name] = self.search_bytes(meth, constant)

    @staticmethod
    def search_bytes(meth, value: bytes):
        # methods returned from StringAnasis is not MethodClassAnalysis,
        # but androguard.core.bytecodes.dvm.EncodedMethod
        # MethodClassAnalysis.get_method() returns a EncodedMethod
        if isinstance(meth, MethodClassAnalysis): 
            if meth.is_external():
                return False
            code = meth.get_method().get_code()
        else:
            code = meth.get_code()
        
        if code:
            return value in code.get_bc().get_raw()
        return False


class AnalyseApkCrypto:
    """ Analyse an APK.

        Accessible attributes:
            app_name: str
                App name of the APK.

            package_name: str
                Package name of the APK.

            classes_with_crypto: dict[str, dict[str, MethInfo]]
                The keys are crypto names, the values are dictionaries,
                whose keys are method names, values are MethInfo objects.
                Only classes or methods that contains crypto names are included.
            
            elf_analyse_result: list[ApkElfAnalyseResult]
                A list of ApkElfAnalyseResult
    """
    def __init__(self, filename):
        self.a, self.d, self.dx = AnalyzeAPK(filename)
        # self.classes_and_methods = self._get_classes_methods()
        # self.classes_with_crypto = {}
        self.methods_with_crypto = {}
        for name in crypto_names:
            # self.classes_with_crypto[name] = {}
            self.methods_with_crypto[name] = {}
        self._get_methods_with_crypto()
        self._get_methods_with_crypto_strings()
        self.elf_analyse_result = analyse_apk_elf(self.a.zip)
        self.package_name = self.a.get_package()
        try:
            self.app_name = self.a.get_app_name()
        except:
            # If we can't get app name, use package name instead
            logger.warning('Failed to get app name, using package name instead.')
            self.app_name = self.package_name
    
    def _get_classes_methods(self):
        results = {}
        classes = self.dx.get_classes()
        for c in classes:
            results[c.name] = []
            for meth in c.get_methods():
                results[c.name].append(meth.name)
        return results

    def _get_methods_with_crypto(self):
        classes = self.dx.get_classes()
        for c in classes:
            crypto_name = match_crypto_name(c.name)
            if crypto_name:     # Class name matches a crypto name
                # All method names of the class are included
                for meth in c.get_methods():
                    self.methods_with_crypto[crypto_name][meth.name] = MethodInfo(meth, c.name)
            else:   # Class name doesn't match
                for meth in c.get_methods():
                    crypto_name = match_crypto_name(meth.name)
                    if crypto_name:
                        # Class name doesn't match but a method does
                        if meth.name not in self.methods_with_crypto[crypto_name]:
                            self.methods_with_crypto[crypto_name][meth.name] = MethodInfo(meth, c.name)

    def _get_methods_with_crypto_strings(self):
        for s in self.dx.get_strings():
            s_value = s.get_orig_value()
            crypto_name = match_crypto_name(s_value, exclude_cert=True)
            if crypto_name:
                for c, meth in s.get_xref_from():
                    if meth.name not in self.methods_with_crypto[crypto_name]:
                        self.methods_with_crypto[crypto_name][meth.name] = MethodInfo(meth, c.name)
                    self.methods_with_crypto[crypto_name][meth.name].strings.add(s_value)


# tests
if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.stderr.write('Need an argument\n')
        sys.exit(1)
    ana = AnalyseApkCrypto(sys.argv[1])
    print(ana.app_name)
    print(ana.package_name)
    print(ana.methods_with_crypto)
