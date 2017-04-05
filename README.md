# pem-key-transformation

Transform public key from .pem file to base16 key. Based on code from AOSP (external/sepolicy/tools/insertkeys.py).

## Usage

``` bash
$ python3 pem_key_transformation.py [-h] [-s SAVE_TO] pem_file
```

* pem_file - absolute path to the .pem file
* -s, --save_to - path to the file where result base16 key should be saved

Example:

``` bash
$ python3 pem_key_transformation.py /path/to/CERT.pem -s /path/to/result.txt
```

