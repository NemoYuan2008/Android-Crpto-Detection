import os
from timeout import timeout
from analyse_apk import AnalyseApkCrypto
from analyse_elf import analyse_apk_elf_with_filename


def write_result(ana: AnalyseApkCrypto, csv_java, csv_elf):
    for class_info in ana.classes_with_crypto.values():
        if class_info.crypto_name_matched:
            csv_java.writerow((ana.app_name, ana.package_name, 
                class_info.matched, class_info.name, '', '', ''))
        for method_info in class_info.method_info.values():
            csv_java.writerow((
                ana.app_name, ana.package_name, 
                class_info.matched, class_info.name, method_info.name, 
                method_info.strings if method_info.strings else '', 
                method_info.crypto_constants_results)
            )
    
    for result in ana.elf_analyse_result:
        csv_elf.writerow([ana.app_name, ana.package_name, result.elf_name] 
        + list(result.symbol_table_with_crypto_name.values())
        + list(result.crypto_constants_results.values()))


@timeout(1000)
def analyse_and_write_result(apk_file, csv_java, csv_elf):
    ana = AnalyseApkCrypto(apk_file)
    write_result(ana, csv_java, csv_elf)


@timeout(1000)
def analyse_and_write_result_elf_only(apk_file, csv_elf):
    results = analyse_apk_elf_with_filename(apk_file)
    for result in results:
        csv_elf.writerow(['', os.path.split(apk_file)[1], result.elf_name] 
        + list(result.symbol_table_with_crypto_name.values())
        + list(result.crypto_constants_results.values()))