import os
from timeout import timeout
from analyse_apk import AnalyseApkCrypto
from analyse_elf import analyse_apk_elf_with_filename


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
def analyse_and_write_result_elf_only(apk_file, csv_elf):
    results = analyse_apk_elf_with_filename(apk_file)
    for result in results:
        csv_elf.writerow(['', os.path.split(apk_file)[1], result.elf_name] 
        + list(result.symbol_table_with_crypto_name.values())
        + list(result.crypto_constants_results.values()))