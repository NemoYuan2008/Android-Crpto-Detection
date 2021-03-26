import sys
import struct
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
                for sym in sec.iter_symbols():
                    result.append(sym.name)
        return result
    
    def search_bytes(self, value: bytes):
        """ Search the value in .rodata, .data, .bss sections.
            Return True on success, False on failure.
        """
        if self.elffile.get_section_by_name('.rodata').data().find(value) != -1:
            return True
        if self.elffile.get_section_by_name('.data').data().find(value) != -1:
            return True
        if self.elffile.get_section_by_name('.bss').data().find(value) != -1:
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
    print(hex(ana.search_bytes_raw(value_to_search)))
