import argparse
import base64
import os
import sys
import re


def parse_arguments():
    """ Parse arguments
    :return tuple of arguments
    """

    parser = argparse.ArgumentParser(description=
        "App for transforming signature from .pem file to base16 format")
    parser.add_argument("pem_file",
        help="absolute path to the .pem file")
    parser.add_argument("-s", "--save_to",
        help="path to the file where result base16 key should be saved",
        default="")

    args = parser.parse_args()
    return args.pem_file, args.save_to


class GenerateKeys(object):
    def __init__(self, path):
        """
        Generates an object with Base16 and Base64 encoded versions of the keys
        found in the supplied pem file argument. PEM files can contain multiple
        certs, however this seems to be unused in Android as pkg manager grabs
        the first cert in the APK. This will however support multiple certs in
        the resulting generation with index[0] being the first cert in the pem
        file.
        """

        self._base64Key = list()
        self._base16Key = list()

        if not os.path.isfile(path):
            sys.exit("Path " + path + " does not exist or is not a file!")

        pkFile = open(path, 'r').readlines()
        base64Key = ""
        lineNo = 1
        certNo = 1
        inCert = False
        for line in pkFile:
            line = line.strip()
            # Are we starting the certificate?
            if line == "-----BEGIN CERTIFICATE-----":
                if inCert:
                    sys.exit("Encountered another BEGIN CERTIFICATE without " +
                             "END CERTIFICATE on line: " + str(lineNo))

                inCert = True

            # Are we ending the ceritifcate?
            elif line == "-----END CERTIFICATE-----":
                if not inCert:
                    sys.exit("Encountered END CERTIFICATE before " +
                             "BEGIN CERTIFICATE on line: " + str(lineNo))

                # If we ended the certificate trip the flag
                inCert = False

                # Sanity check the input
                if len(base64Key) == 0:
                    sys.exit("Empty certficate , certificate " + str(certNo) +
                             " found in file: " + path)

                # ... and append the certificate to the list
                # Base 64 includes uppercase. DO NOT tolower()
                self._base64Key.append(base64Key)
                try:
                    # Pkgmanager and setool see hex strings with lowercase,
                    # lets be consistent
                    self._base16Key.append(base64.b16encode(base64.b64decode(base64Key)).lower())
                except TypeError:
                    sys.exit("Invalid certificate, certificate " +
                             str(certNo) + " found in file: " + path)

                # After adding the key, reset the accumulator as pem files
                # may have subsequent keys
                base64Key = ""

                # And increment your cert number
                certNo = certNo + 1

            # If we haven't started the certificate, then we should not record
            # any data
            elif not inCert:
                lineNo += 1
                continue

            # else we have started the certificate and need to append the data
            elif inCert:
                base64Key += line

            else:
                # We should never hit this assert, if we do then an unaccounted
                # for state was entered that was NOT addressed by the
                # if/elif statements above
                assert(False == True)

            # The last thing to do before looping up is to increment line number
            lineNo = lineNo + 1

    def __len__(self):
        return len(self._base16Key)

    def __str__(self):
        return str(self.getBase16Keys())

    def getBase16Keys(self):
        return self._base16Key

    def getBase64Keys(self):
        return self._base64Key


def print_keys(t_keys):
    print("Keys in base16 format:")
    for i, key in enumerate(t_keys):
        print(str(i + 1) + ": " + clean_up_key(str(key)))


def save_keys_to_file(t_keys, t_file):
    print("Writing to file: " + t_file)
    with open(t_file, 'w') as file:
        for key in t_keys:
            file.write(clean_up_key(str(key)) + '\n')


def clean_up_key(t_key):
    t_key = re.compile("^b'").sub("", t_key)
    t_key = re.compile("'$").sub("", t_key)
    return t_key


if __name__ == "__main__":
    arguments = parse_arguments()

    obj = GenerateKeys(arguments[0])
    if len(arguments[1]) <= 0:
        print_keys(obj.getBase16Keys())
    else:
        save_keys_to_file(obj.getBase16Keys(), arguments[1])
