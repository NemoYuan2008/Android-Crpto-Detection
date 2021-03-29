import sys
import csv
from zipfile import BadZipFile
from analyse_apk import AnalyseApkCrypto

def write_csv(csv_writer, ana):
    for crypto_name, class_dict in ana.classes_with_crypto.items():
            for class_name, methods in class_dict.items():
                for method in methods:
                    if isinstance(method, tuple):
                        csv_writer.writerow([ana.app_name, ana.package_name, crypto_name, class_name, method[0], method[1]])
                    else:
                        csv_writer.writerow([ana.app_name, ana.package_name, crypto_name, class_name, method])


if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.stderr.write('Need an argument\n')
        sys.exit(1)

    with open('result.csv', 'w', newline='') as f:
        csv_writer = csv.writer(f)
        csv_writer.writerow(['App Name', 'Package Name', 'Crypto Name', 'Class', 'Methods', 'Strings'])
        
        for filename in sys.argv[1:]:
            print('Analysing %s' % filename)
            try:
                ana = AnalyseApkCrypto(filename)
            except:
                sys.stderr.write('Ignoring %s: not an APK file.\n' % filename)
                continue
            write_csv(csv_writer, ana)
