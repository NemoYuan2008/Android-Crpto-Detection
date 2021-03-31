import sys
import struct
import zipfile
import operator
from typing import NamedTuple
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from constants import sm4_sbox, sm4_ck
from crypto_names import *

class AnalyseElf:
    def __init__(self, file):
        self._f = file
        self.elffile = ELFFile(file)
        self.symbol_table = self._get_symbol_table()
        self.symbol_table_with_crypto_name = {}
        for crypto_name in crypto_names:
            self.symbol_table_with_crypto_name[crypto_name] = []
        self._get_symbol_table_with_crypto_name()

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


class ApkElfAnalyseResult(NamedTuple):
    pass


def analyse_apk_elf(filename):
    with zipfile.ZipFile(filename, 'r') as apk_zip:
        for name in filter(lambda s: s.startswith('lib') and s.endswith('.so'), apk_zip.namelist):
            print(name)
            with apk_zip.open(name) as elffile:
                ana = AnalyseElf(elffile)
                print(ana.symbol_table_with_crypto_name)
                print(ana.search_bytes(sm4_sbox))
                print(ana.search_bytes(sm4_ck))


if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.stderr.write('Need an arguement\n')
        sys.exit(1)

    for filename in sys.argv[1:]:
        try:
            analyse_apk_elf(filename)
        except zipfile.BadZipFile:
            sys.stderr.write('Ignoring %s: not an APK file.\n' % filename)
