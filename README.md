# Android Crypto Detection - Detect SM Ciphers in APK

## Usage

```
python3 main.py [-h] [--elf-only] [-o OUTPUT] apk_file [apk_file ...]

positional arguments:
  apk_file              APK files to be analysed

optional arguments:
  -h, --help            show this help message and exit
  --elf-only            only analyse elf files in APK
  -o OUTPUT, --output OUTPUT
                        a directory to save output file
```

## Notes

`Androguard` and `pyelftools` are required. `Androguard 3.3.5` (see [requirements.txt](./requirements.txt)) is recommended, because version `3.4.0` is currently unstable and it's API differs a lot from version `3.3.5` . 