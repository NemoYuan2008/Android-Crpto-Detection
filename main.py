import os
import sys
import csv
import argparse
import logging
from time import time
from zipfile import BadZipFile
from analyse_apk import AnalyseApkCrypto
from analyse_elf import analyse_apk_elf_with_filename
from constants import crypto_constants
from crypto_names import crypto_names
from timeout import timeout
from colored_logger import file_formatter, terminal_formatter


def write_result(ana: AnalyseApkCrypto, csv_java, csv_elf):
    for crypto_name, meth_dict in ana.methods_with_crypto.items():
        for meth_name, meth_info in meth_dict.items():
            if not meth_info.strings:
                meth_info.strings = ''
            csv_java.writerow([ana.app_name, ana.package_name, crypto_name, 
                               meth_info.class_name, meth_name, meth_info.strings]
                               + list(meth_info.crypto_constants_results.values()))
    
    for result in ana.elf_analyse_result:
        csv_elf.writerow([ana.app_name, ana.package_name, result.elf_name] 
        + list(result.symbol_table_with_crypto_name.values())
        + list(result.crypto_constants_results.values()))


@timeout(600)
def analyse_and_write_result(apk_file, csv_java, csv_elf):
    ana = AnalyseApkCrypto(apk_file)
    write_result(ana, csv_java, csv_elf)


@timeout(600)
def write_result_elf_only(apk_file, csv_elf):
    results = analyse_apk_elf_with_filename(apk_file)
    for result in results:
        csv_elf.writerow(['', os.path.split(apk_file)[1], result.elf_name] 
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

    logger = logging.getLogger('AndroidCryptoDetection')
    logger.setLevel(logging.DEBUG)
    handler = logging.StreamHandler()
    handler.setFormatter(terminal_formatter)
    logger.addHandler(handler)
    handler = logging.FileHandler(os.path.join(path, 'analyse_log.log'))
    handler.setFormatter(file_formatter)
    logger.addHandler(handler)


    if args.elf_only:
        logger.warning('ELF-only mode, file name will be used instead of package name')
    else:
        f_java = open(os.path.join(path, 'result_java.csv'), 'w', newline='')
        csv_java = csv.writer(f_java)
        csv_java.writerow(['App Name', 'Package Name', 'Crypto Name', 'Class', 'Methods', 'Strings'] + list(crypto_constants.keys()))
    f_elf = open(os.path.join(path, 'result_elf.csv'), 'w', newline='')
    csv_elf = csv.writer(f_elf)
    csv_elf.writerow(['App Name', 'Package Name', 'ELF Name'] + crypto_names + list(crypto_constants.keys()))
    f_time = open(os.path.join(path, 'result_time.csv'), 'w', newline='')
    csv_time = csv.writer(f_time)
    csv_time.writerow(['App File Name', 'Time Consumed/s'])

    for apk_file in args.apk_file:
        if os.path.isdir(apk_file):
            continue
        logger.info('Analysing {}'.format(apk_file))

        time_start = time()

        try:
            if args.elf_only:
                write_result_elf_only(apk_file, csv_elf)
            else:   # Analyse both Java and native
                analyse_and_write_result(apk_file, csv_java, csv_elf)
        except KeyboardInterrupt:   # timed out
            logger.error('Analyse of {} timed out'.format(apk_file))
            csv_time.writerow([os.path.split(apk_file)[1], 'timed out'])
            continue
        except BadZipFile:
            logger.warning('Ignoring {}: not an APK file'.format(apk_file))
            continue
        except Exception as e: # Handle unexpected exceptions raised by androguard
            logger.critical(e)
            continue

        time_consumed = int(time() - time_start)
        logger.debug('Analyse of {} consumed {} seconds'.format(apk_file, time_consumed))
        csv_time.writerow([os.path.split(apk_file)[1], time_consumed])

    if not args.elf_only:
        f_java.close()
    f_elf.close()
    f_time.close()
