import os
import io
import sys
import zipfile
import operator
import logging
from typing import NamedTuple
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.common.exceptions import ELFError
from constants import crypto_constants
from crypto_names import *

logger = logging.getLogger('AndroidCryptoDetection')

class AnalyseElf:
    """ Analyse an ELF file.

        Accessible attributes:
            symbol_table: list[str]
                A list of symbol names in ELF
                
            symbol_table_with_crypto_name: dict[str, list[str]]
                The keys are crypto names, the values are lists of symbol names
                which contains the crypto names
            
            crypto_constants_result: dict[str, bool]
                The keys are crypto constants names, e.g., sm4_ck, sm4_sbox.
                The values are bools indicating whether the constant is found in ELF.
    """

    def __init__(self, stream, filename=None):
        self._f = stream
        _, self.elf_name = os.path.split(filename)
        self.elffile = ELFFile(stream)
        self.symbol_table = self._get_symbol_table()
        self.symbol_table_with_crypto_name = {}
        for crypto_name in crypto_names:
            self.symbol_table_with_crypto_name[crypto_name] = []
        self._get_symbol_table_with_crypto_name()
        self.crypto_constants_result = {}
        self._get_crypto_constants_result()

    def get_analyse_result(self):
        return ApkElfAnalyseResult(self.elf_name, self.symbol_table_with_crypto_name, self.crypto_constants_result)

    def _get_symbol_table(self):
        """ Return a list of symbol names in the ELF file.
        """
        result = []
        for sec in self.elffile.iter_sections():
            if isinstance(sec, SymbolTableSection):
                result += list(map(operator.attrgetter('name'), sec.iter_symbols()))
        return result
    
    def _get_symbol_table_with_crypto_name(self):
        for symbol in self.symbol_table:
            crypto_name = match_crypto_name(symbol)
            if crypto_name is not None:
                self.symbol_table_with_crypto_name[crypto_name].append(symbol)

    def search_bytes(self, value: bytes):
        """ Search the value in .rodata, .data, .bss sections.
            Return True on success, False on failure.
        """
        sec = self.elffile.get_section_by_name('.rodata')
        if sec is not None and value in sec.data():
            return True

        sec = self.elffile.get_section_by_name('.data')
        if sec is not None and value in sec.data():
            return True

        sec = self.elffile.get_section_by_name('bss')
        if sec is not None and value in sec.data():
            return True
        return False

    def search_bytes_raw(self, value: bytes):
        """ Search the value in the whole file.
            Return the address on success, -1 on failure.
            May be time and memory consuming.
        """
        self._f.seek(0)
        buffer = self._f.read()
        return buffer.find(value)

    def _get_crypto_constants_result(self):
        for name, constant in crypto_constants.items():
            self.crypto_constants_result[name] = self.search_bytes(constant)


class ApkElfAnalyseResult(NamedTuple):
    elf_name: str
    symbol_table_with_crypto_name: dict
    crypto_constants_results: dict

pack_elf_name = {
    "libchaosvmp.so", "libddog.so", "libfdog.so",
    "libexec.so", "libexecmain.so", "ijiami.so",
    "libsecexe.so", "libsecmain.so", "libDexHelper.so",
    "libprotectClass.so", "libjiagu.so", "libjiagu_art.so", "libjiagu_x86.so",
    "libegis.so", "libNSaferOnly.so",
    "libnqshield.so",
    "libbaiduprotect.so",
    "libshellx-2.10.6.0.so", "libBugly.so", "libtup.so", "libexec.so", "libshell.so",
    "aliprotect.so", "libsgmain.so", "libsgsecuritybody.so",
    "libtosprotection.armeabi.so", "libtosprotection.armeabi-v7a.so", "libtosprotection.x86.so",
    "libnesec.so",
    "libAPKProtect.so",
    "libkwscmm.so", "libkwscr.so", "libkwslinker.so"
}

def analyse_apk_elf(apk_zip: zipfile.ZipFile):
    ret_val = []
    pack_elf = []
    for name in filter(lambda s: s.startswith('lib') and s.endswith('.so'), apk_zip.namelist()):
        with apk_zip.open(name) as elffile:
            with io.BytesIO(elffile.read()) as elffile:
                try:
                    ret_val.append(AnalyseElf(elffile, name).get_analyse_result())
                except ELFError:
                    logger.warning('Ignoring {}: not an ELF'.format(name))
                    continue
        name = os.path.split(name)[1]
        if name in pack_elf_name or 'libshellx' in name:
            pack_elf.append(name)
    return ret_val, pack_elf


def analyse_apk_elf_with_filename(filename):
    with zipfile.ZipFile(filename, 'r') as apk_zip:
        return analyse_apk_elf(apk_zip)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.stderr.write('Need an arguement\n')
        sys.exit(1)

    for filename in sys.argv[1:]:
        try:
            print(analyse_apk_elf_with_filename(filename))
        except zipfile.BadZipFile:
            sys.stderr.write('Ignoring %s: not an APK file.\n' % filename)
