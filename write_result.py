from analyse_apk import AnalyseApkCrypto


def write_result(ana: AnalyseApkCrypto, time_consumed, csv_java, csv_elf, csv_overview):
    for class_info in ana.classes_with_crypto.values():
        if class_info.crypto_name_matched:
            csv_java.writerow((ana.app_name, ana.package_name, 
                class_info.matched, class_info.name, '', '', ''))
        for method_info in class_info.method_info.values():
            csv_java.writerow((
                ana.app_name, ana.package_name, 
                method_info.matched, class_info.name, method_info.name, 
                method_info.strings if method_info.strings else '', 
                method_info.crypto_constants_results)
            )
    
    for result in ana.elf_analyse_result:
        csv_elf.writerow([ana.app_name, ana.package_name, result.elf_name] 
        + list(result.symbol_table_with_crypto_name.values())
        + list(result.crypto_constants_results.values()))
    
    csv_overview.writerow((ana.app_name, ana.package_name, time_consumed, 
        ana.class_cnt, ana.method_cnt, ana.elf_cnt, ana.pack_elf))
