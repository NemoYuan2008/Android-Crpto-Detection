import os
import sys
import csv
import argparse
from zipfile import BadZipFile
from analyse_apk import AnalyseApkCrypto
from constants import crypto_constants
from crypto_names import crypto_names

def write_result(ana: AnalyseApkCrypto, csv_java, csv_elf):
    csv_java = csv.writer(f_java)
    csv_elf = csv.writer(f_elf)
    
    for crypto_name, class_dict in ana.classes_with_crypto.items():
        for class_name, methods in class_dict.items():
            for method in methods:
                if isinstance(method, tuple):
                    csv_java.writerow([ana.app_name, ana.package_name, crypto_name, class_name, method[0], method[1]])
                else:
                    csv_java.writerow([ana.app_name, ana.package_name, crypto_name, class_name, method])
    
    for result in ana.elf_analyse_result:
        csv_elf.writerow([ana.app_name, ana.package_name, result.elf_name] 
        + list(result.symbol_table_with_crypto_name.values())
        + list(result.crypto_constants_results.values()))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--elf-only', action='store_true', help='only analyse elf files in APK')
    parser.add_argument('apk_file', nargs='+', help='APK files to be analysed')
    parser.add_argument('-o', '--output', default='./', help='a directory to save output file')
    args = parser.parse_args()

    path = args.output
    if not os.path.isdir(path):
        os.mkdir(path)

    with open(os.path.join(path, 'result_java.csv'), 'w', newline='') as f_java, open(os.path.join(path, 'result_elf.csv'), 'w', newline='') as f_elf:
        csv_java = csv.writer(f_java)
        csv_elf = csv.writer(f_elf)
        csv_java.writerow(['App Name', 'Package Name', 'Crypto Name', 'Class', 'Methods', 'Strings'])
        csv_elf.writerow(['App Name', 'Package Name', 'ELF Name'] + crypto_names + list(crypto_constants.keys()))

        for apk_file in args.apk_file:
            try:
                ana = AnalyseApkCrypto(apk_file)
                write_result(ana, csv_java, csv_elf)
            except BadZipFile:
                sys.stderr.write('Ignoring %s: not an APK file.\n' % apk_file)
                continue
