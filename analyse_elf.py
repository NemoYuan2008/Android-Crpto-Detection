import sys
import struct
import operator
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection


class AnalyseElf:
    def __init__(self, filename):
        self.filename = filename
        self._f = open(filename, 'rb')
        self.elffile = ELFFile(self._f)
    
    def __del__(self):
        self._f.close()

    def analyse_symbol_table(self):
        """ Return a list of symbol names in the ELF file.
        """
        result = []
        for sec in self.elffile.iter_sections():
            if isinstance(sec, SymbolTableSection):
                result += list(map(operator.attrgetter('name'), sec.iter_symbols()))
        return result
    
    def search_bytes(self, value: bytes):
        """ Search the value in .rodata, .data, .bss sections.
            Return True on success, False on failure.
        """
        if value in self.elffile.get_section_by_name('.rodata').data():
            return True
        if value in self.elffile.get_section_by_name('.data').data():
            return True
        if value in self.elffile.get_section_by_name('.bss').data():
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



if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.stderr.write('Need an arguement\n')
        sys.exit(1)

    # Test case: ~/Desktop/apk/boc/lib/armeabi/libWDMobileKeySDKLib.so
    ana = AnalyseElf(sys.argv[1])

    print(ana.analyse_symbol_table())

    ck = [0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269]
    value_to_search = struct.pack('<IIII', *ck)
    print(ana.search_bytes(value_to_search))
    print(hex(ana.search_bytes_raw(value_to_search)))
