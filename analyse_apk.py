import sys
from androguard.misc import AnalyzeAPK

def analyse_apk(filename):
    a, d, dx = AnalyzeAPK(filename)
    f = open(filename + '.out.txt', 'w')

    f.write(a.get_package() + '\n')
    f.write(a.get_app_name() + '\n\n')

    classes = dx.get_classes()
    for c in classes:
        f.write(c.name + '\n')
        methods = c.get_methods()
        for method in methods:
            f.write('\t' + method.name + '\n')
    
    f.close()


if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.stderr.write('Need an arguement\n')
        sys.exit(1)
    analyse_apk(sys.argv[1])
