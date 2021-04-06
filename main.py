import os
import sys
import csv
import argparse
import logging
from zipfile import BadZipFile
from analyse_apk import AnalyseApkCrypto
from constants import crypto_constants
from crypto_names import crypto_names
from timeout import timeout
from colored_logger import ColoredFormatter


def write_result(ana: AnalyseApkCrypto, csv_java, csv_elf):
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


@timeout(300)
def analyse_and_write_result(apk_file, csv_java, csv_elf):
    ana = AnalyseApkCrypto(apk_file)
    write_result(ana, csv_java, csv_elf)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--elf-only', action='store_true', help='only analyse elf files in APK')
    parser.add_argument('apk_file', nargs='+', help='APK files to be analysed')
    parser.add_argument('-o', '--output', default='./', help='a directory to save output file')
    args = parser.parse_args()

    path = args.output
    if not os.path.isdir(path):
        os.mkdir(path)

    logger = logging.getLogger('AndroidCryptoDetection')
    logger.setLevel(logging.DEBUG)
    handler = logging.StreamHandler()
    handler.setFormatter(ColoredFormatter())
    logger.addHandler(handler)
    handler = logging.FileHandler(os.path.join(path, 'analyse_log.log'))
    handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', '%H:%M:%S'))
    logger.addHandler(handler)

    with open(os.path.join(path, 'result_java.csv'), 'w', newline='') as f_java, open(os.path.join(path, 'result_elf.csv'), 'w', newline='') as f_elf:
        csv_java = csv.writer(f_java)
        csv_elf = csv.writer(f_elf)
        csv_java.writerow(['App Name', 'Package Name', 'Crypto Name', 'Class', 'Methods', 'Strings'])
        csv_elf.writerow(['App Name', 'Package Name', 'ELF Name'] + crypto_names + list(crypto_constants.keys()))

        for apk_file in args.apk_file:
            if os.path.isdir(apk_file):
                continue
            logger.info('Analysing {}'.format(apk_file))

            try:
                analyse_and_write_result(apk_file, csv_java, csv_elf)
            except KeyboardInterrupt:   # timed out
                logger.error('Analyse of {} timed out'.format(apk_file))
            except BadZipFile:
                logger.warning('Ignoring {}: not an APK file'.format(apk_file))
