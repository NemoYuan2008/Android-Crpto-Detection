import sys
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

def analyse_symboltable(filename):
    with open(filename, 'rb') as f, open(filename + '.out.txt', 'w') as f_out:
        elffile = ELFFile(f)
        for sec in elffile.iter_sections():
            if isinstance(sec, SymbolTableSection):
                for sym in sec.iter_symbols():
                    f_out.write(sym.name + '\n')


if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.stderr.write('Need an arguement\n')
        sys.exit(1)
    analyse_symboltable(sys.argv[1])
