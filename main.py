import os
import csv
import argparse
import logging
from time import time
from zipfile import BadZipFile
from constants import crypto_constants
from crypto_names import crypto_names
from colored_logger import file_formatter, terminal_formatter
from write_result import *


if __name__ == '__main__':
    # Parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('--elf-only', action='store_true', help='only analyse elf files in APK')
    parser.add_argument('apk_file', nargs='+', help='APK files to be analysed')
    parser.add_argument('-o', '--output', default='./', help='a directory to save output file')
    args = parser.parse_args()

    path = args.output
    if not os.path.isdir(path):
        os.mkdir(path)

    # Setup the logger
    logger = logging.getLogger('AndroidCryptoDetection')
    logger.setLevel(logging.DEBUG)
    handler = logging.StreamHandler()
    handler.setFormatter(terminal_formatter)
    logger.addHandler(handler)
    handler = logging.FileHandler(os.path.join(path, 'analyse_log.log'))
    handler.setFormatter(file_formatter)
    logger.addHandler(handler)

    # Open CSV files
    if args.elf_only:
        logger.warning('ELF-only mode, file name will be used instead of package name')
    else:
        f_java = open(os.path.join(path, 'result_java.csv'), 'w', newline='')
        csv_java = csv.writer(f_java)
        csv_java.writerow(('App Name', 'Package Name', 'Crypto Name', 'Class', 'Method', 'Strings', 'Constants'))
    f_elf = open(os.path.join(path, 'result_elf.csv'), 'w', newline='')
    csv_elf = csv.writer(f_elf)
    csv_elf.writerow(['App Name', 'Package Name', 'ELF Name'] + crypto_names + list(crypto_constants.keys()))
    f_time = open(os.path.join(path, 'result_time.csv'), 'w', newline='')
    csv_time = csv.writer(f_time)
    csv_time.writerow(['App File Name', 'Time Consumed/s'])

    # Run the analysis
    for apk_file in args.apk_file:
        if os.path.isdir(apk_file):
            continue
        logger.info('Analysing {}'.format(apk_file))

        time_start = time()

        try:
            if args.elf_only:
                analyse_and_write_result_elf_only(apk_file, csv_elf)
            else:   # Analyse both Java and native
                analyse_and_write_result(apk_file, csv_java, csv_elf)
        except KeyboardInterrupt:   # timed out
            logger.error('Analyse of {} timed out'.format(apk_file))
            csv_time.writerow([os.path.split(apk_file)[1], 'timed out'])
            continue
        except BadZipFile:
            logger.warning('Ignoring {}: not an APK file'.format(apk_file))
            continue
        # except Exception as e:      # Handle unexpected exceptions raised by androguard
        #     logger.critical(e)
        #     continue

        time_consumed = int(time() - time_start)
        logger.debug('Analyse of {} consumed {} seconds'.format(apk_file, time_consumed))
        csv_time.writerow([os.path.split(apk_file)[1], time_consumed])

    if not args.elf_only:
        f_java.close()
    f_elf.close()
    f_time.close()
