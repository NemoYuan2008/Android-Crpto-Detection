import sys
import logging
from androguard.misc import AnalyzeAPK
from androguard.core.analysis.analysis import ClassAnalysis
from crypto_names import match_crypto_name
from analyse_elf import analyse_apk_elf
from constants import crypto_constants


logger = logging.getLogger('AndroidCryptoDetection')


class MethodCryptoAnalysis:
    """ Analyse a method in a Java class

        Accessible attributes:
            name: str
                The name of the method
            
            crypto_name_matched: str
                The crypto name matched for the method name, or None if class name doesn't match.
                Note: this variable indicates whether method name itself matches,
                    regardless whether the method contains constants related to crypto.
            
            strings: list[str]
                Strings that is related to crypto and used by the method
            
            crypto_constants_results: list[str]
                Names of crypto constants (defined in `constants.py`) that are found in the method
    """
    def __init__(self, meth):
        self.strings = set()
        self.crypto_constants_results = []

        if isinstance(meth, str):
            self.name = meth
            self.crypto_name_matched = None
            return
        
        self.name = meth.name
        self.crypto_name_matched = match_crypto_name(self.name)

        for name, constant in crypto_constants.items():
            if self.search_bytes(meth, constant):
                self.crypto_constants_results.append(name)
    
    def add_string(self, s):
        self.strings.add(s)

    @property
    def matched(self):
        """ Return the crypto name that this method related to, 
            return None if this method isn't related to any crypto.
        """
        if self.crypto_name_matched is not None:
            return self.crypto_name_matched
        if self.crypto_constants_results:
            return self.crypto_constants_results[0].split('_')[0]
        if self.strings:
            for dummy in self.strings:
                return match_crypto_name(dummy)
        return None

    @staticmethod
    def search_bytes(meth, value: bytes):
        if meth.is_external():
            return False
        code = meth.get_method().get_code()        
        if code:
            return value in code.get_bc().get_raw()
        return False
    
    def __repr__(self) -> str:
        ret = (
            'Method name: {}'.format(self.name), 
            'Crypto name: {}'.format(self.crypto_name_matched), 
            'Strings: {}'.format(self.strings), 
            'Constants: {}'.format(self.crypto_constants_results),
            ''
        )
        return '\n'.join(ret)


class ClassCryptoAnalysis:
    """ Analyse a Java class

        Accessible attributes:
            name: str
                The name of the class

            crypto_name_matched: str
                The crypto name matched for the class name, or None if class name doesn't match.
                Note: this variable indicates whether class name itself matches,
                    regardless whether it's method is matched.
            
            method_info: dict[str, MethodCryptoAnalysis]
                Contains the methods of the class that has one of the following properties:
                    matches the name or contain strings or contain constants related to crypto.
                The keys are method names, the values are MethodCryptoAnalysis objects.
    """
    def __init__(self, class_ana: ClassAnalysis, from_str=False):
        self.name = class_ana.name
        self.method_info = {}

        if from_str: 
            # Needn't search every method again.
            self.crypto_name_matched = None
            return

        self.crypto_name_matched = match_crypto_name(class_ana.name)
        for meth in class_ana.get_methods():
            meth_ana = MethodCryptoAnalysis(meth)
            if meth_ana.matched:
                self.method_info[meth_ana.name] = meth_ana
    
    @property
    def matched(self):
        """ Return the crypto name that this class and it's methods related to, 
            return None if this class or it's methods isn't related to any crypto.
        """
        if self.crypto_name_matched is not None:
            return self.crypto_name_matched
        if self.method_info:
            for dummy in self.method_info.values():
                return dummy.matched
        return None

    def add_string(self, meth_name, s):
        if meth_name in self.method_info:
            self.method_info[meth_name].add_string(s)
        else:
            ana = MethodCryptoAnalysis(meth_name)
            ana.add_string(s)
            self.method_info[meth_name] = ana
    
    def __repr__(self) -> str:
        ret = (
            'Class name: {}'.format(self.name),
            'Class crypto name: {}'.format(self.crypto_name_matched),
            'Method info:\n{}'.format(self.method_info.values()),
            ''
        )
        return '\n'.join(ret) + '\n'


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
        self.classes_with_crypto = {}
        self.elf_analyse_result, self.pack_elf = analyse_apk_elf(self.a.zip)
        self.package_name = self.a.get_package()
        self.method_cnt = len(list(self.dx.get_methods()))
        self.class_cnt = len(list(self.dx.get_classes()))
        self.elf_cnt = len(self.elf_analyse_result)

        try:
            self.app_name = self.a.get_app_name()
        except:
            # If we can't get app name, use package name instead
            logger.warning('Failed to get app name, using package name instead.')
            self.app_name = self.package_name
        
        self._get_classes_with_crypto()
        self._get_classes_with_crypto_strings()
    
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
            ana = ClassCryptoAnalysis(c)
            if ana.matched:
                self.classes_with_crypto[ana.name] = ana

    def _get_classes_with_crypto_strings(self):
        for s_ana in self.dx.get_strings():
            s_value = s_ana.get_orig_value()
            crypto_name = match_crypto_name(s_value, exclude_cert=True)
            if crypto_name:
                for c, meth in s_ana.get_xref_from():
                    # Type of c is androguard.core.analysis.analysis.ClassAnalysis
                    # Type of meth is androguard.core.bytecodes.dvm.EncodedMethod
                    if c.name in self.classes_with_crypto:
                        self.classes_with_crypto[c.name].add_string(meth.name, s_value)
                    else:
                        class_ana = ClassCryptoAnalysis(c, from_str=True)
                        class_ana.add_string(meth.name, s_value)
                        self.classes_with_crypto[c.name] = class_ana
    
    def __repr__(self) -> str:
        ret = (
            'App name: {}'.format(self.app_name),
            'Package name: {}'.format(self.package_name), 
            'Class info:\n{}'.format(self.classes_with_crypto.values()),
        )
        return '\n'.join(ret)


# tests
if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.stderr.write('Need an argument\n')
        sys.exit(1)
    ana = AnalyseApkCrypto(sys.argv[1])
    print(ana)
