import sys
from androguard.misc import AnalyzeAPK


class AnalyseApk:
    def __init__(self, filename):
        self.a, self.d, self.dx = AnalyzeAPK(filename)
        self.classes_and_methods = self._get_classes_methods()
    
    def _get_classes_methods(self):
        results = {}
        classes = self.dx.get_classes()
        for c in classes:
            results[c.name] = []
            for meth in c.get_methods():
                results[c.name].append(meth.name)
        return results


if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.stderr.write('Need an arguement\n')
        sys.exit(1)
    ana = AnalyseApk(sys.argv[1])
    print(ana.classes_and_methods)
