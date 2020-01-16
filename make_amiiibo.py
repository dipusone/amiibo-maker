#!/usr/bin/env python3
import argparse
import atexit
import binascii
import nfc
import requests
import sys
import time

from amiibo import AmiiboDump, AmiiboMasterKey
from amiibo.crypto import AmiiboHMACError, AmiiboHMACTagError, AmiiboDumpSizeError
from functools import wraps

try:
    import ueberzug.lib.v0 as ueberzug
    import shutil

    from tempfile import NamedTemporaryFile
    HAS_UEBERZUG = True
except ImportError:
    HAS_UEBERZUG = False


EXIT_FAILURE = -1
EXIT_SUCCESS = 0

URL = "https://www.amiiboapi.com/api/amiibo/"
VERBOSE = False
ncf_reader = None
device = 'usb'


def uid_to_hex_format(uid):
    if len(uid) != 14:
        print_error("Uid must be 14 character (7 bytes) long")
        sys.exit(EXIT_FAILURE)
    split_uuid = " ".join([uid[i:i + 2] for i in range(0, len(uid), 2)])
    return split_uuid.upper()


def download_and_show_image(url, width=25, height=25, xpad=5):

    if not HAS_UEBERZUG:
        return

    columns, _ = shutil.get_terminal_size((80, 20))
    with ueberzug.Canvas() as c, NamedTemporaryFile() as image:
        res = requests.get(url, stream=True)
        shutil.copyfileobj(res.raw, image)
        image.flush()
        amiibo_image = c.create_placement('amiibo_image',
                                          x=columns - width - xpad,
                                          y=0,
                                          max_width=width,
                                          max_height=height,
                                          scaler=ueberzug.ScalerOption.FIT_CONTAIN.value)
        amiibo_image.path = image.name
        amiibo_image.visibility = ueberzug.Visibility.VISIBLE

        input("Press return to end preview\n")


def print_amiibo_details(data, show_image=False):
    amibo_id = binascii.hexlify(data[0x54:0x5c]).decode('utf-8')
    resp = requests.get(URL, {'id': amibo_id})
    if resp.status_code != 200:
        print_error("No amiibo details available")
        return
    amiibo = resp.json()
    print('\n', end='')
    print("Character    :", amiibo['amiibo']['character'])
    print("Full Name    :", amiibo['amiibo']['name'])
    print("Game Series  :", amiibo['amiibo']['gameSeries'])
    print("Amiibo Series:", amiibo['amiibo']['amiiboSeries'])
    print("Image url    :", amiibo['amiibo']['image'], '\n')
    if show_image:
        download_and_show_image(amiibo['amiibo']['image'])


def calc_password(iuid):
    uid = binascii.unhexlify(iuid)
    assert uid[0] == 0x04
    password = bytes([
        0xAA ^ uid[1] ^ uid[3],
        0x55 ^ uid[2] ^ uid[4],
        0xAA ^ uid[3] ^ uid[5],
        0x55 ^ uid[4] ^ uid[6],
    ])
    return binascii.hexlify(password).decode('utf-8')


def make_new_amiibo(unfixed_info, locked_key, amiibo_data, uid):
    try:
        master_keys = AmiiboMasterKey.from_separate_bin(unfixed_info.read(),
                                                        locked_key.read())
    except ValueError as e:
        print_error("Invalid keys: " + str(e))
        sys.exit(EXIT_FAILURE)
    try:
        amiibo = AmiiboDump(master_keys, amiibo_data)
        amiibo.unlock()
    except (AmiiboHMACError, AmiiboHMACTagError, AmiiboDumpSizeError):
        print_error("This amiibo is invalid or corrupt")
        sys.exit(EXIT_FAILURE)
    amiibo.uid_hex = uid_to_hex_format(uid)
    amiibo.lock()
    amiibo.unset_lock_bytes()
    return amiibo


def with_nfc_reader(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        global ncf_reader
        global device
        if not ncf_reader:
            print_info("Opening the reader")
            init_reader(device or 'usb')
        return func(*args, **kwargs)
    return wrapper


def init_reader(id='usb'):
    global ncf_reader
    try:
        ncf_reader = nfc.ContactlessFrontend(id)
    except IOError as e:
        print_error("Unable to find the reader", str(e))
        print_error("Execute python -m nfc to get any locking program")
        sys.exit(EXIT_FAILURE)


@atexit.register
def close_nfc_reader():
    global ncf_reader
    if ncf_reader:
        print_info("Closing the reader")
        # the normal close method leaves the reader in an instable state
        ncf_reader.device.chipset.close()


@with_nfc_reader
def get_tag(timeout=5, silent=False):
    if not silent:
        print_info("Waiting %d seconds for the tag to appear" % timeout)
    started = time.time()
    tag = ncf_reader.connect(rdwr={'on-connect': lambda tag: False},
                             terminate=lambda: time.time() - started > timeout)
    return tag


@with_nfc_reader
def read_from_tag():
    data = bytes()
    for i in range(0x87):
        try:
            block = tag.read(i)[:4]
        except Exception as e:
            print_error("Error while reading the card: " + str(e))
            break
        if VERBOSE:
            print_page(i, block, end='\n')
        data += block
    return data


@with_nfc_reader
def write_to_tag(tag, input_data, write_retry=5):
    STATIC_BLOCK_PAGE = 0x2
    DYN_BLOCK_PAGE = 0x82
    DynamicLockBlock = bytes([0x01, 0x00, 0x0F, 0xBD])
    StaticLockBlock = bytes([0x0F, 0xE0, 0x0F, 0xE0])
    retry = 0

    # The first two pages contains the card uid an checksums
    # the third page contains the static lock bytes that we write at the end
    for page in range(0x3, 0x87):
        block = input_data[page * 4: (page + 1) * 4]
        if page in (STATIC_BLOCK_PAGE, DYN_BLOCK_PAGE):
            continue
        if VERBOSE:
            print_page(page, block)
        try:
            tag.write(page, block)
            retry = 0
            if VERBOSE:
                print()
        except Exception as e:
            retry += 1
            if retry >= write_retry:
                if VERBOSE:
                    print()
                print_error("Reached max write attemps of " + str(write_retry))
                return
            tag = get_tag(timeout=1, silent=True)
            print_error(str(e), prefix=":")
    # Write the dynamic locks
    try:
        print_verbose("Writing Dynamic Locks")
        tag.write(DYN_BLOCK_PAGE, DynamicLockBlock)
    except Exception:
        if not VERBOSE:
            print()
        print_error("Unable to write Dynamic Locks")
    # Write the static locks
    try:
        print_verbose("Writing Static Locks")
        tag.write(STATIC_BLOCK_PAGE, StaticLockBlock)
    except Exception:
        print_error("Unable to write Static Locks")


def print_page(idx, data, end=''):
    print("%2X: " % idx, end='')
    for byte in data:
        print("%2X " % byte, end='')
    print(end, end='')


def print_info(msg, prefix='[+]', end='\n'):
    print("{} {}".format(prefix, msg), end=end, flush=True)


def print_error(msg, prefix='[-]', end='\n'):
    print_info(msg, prefix, end)


def print_verbose(msg, prefix='[*]', end='\n'):
    if VERBOSE:
        print_info(msg, prefix, end)


def arg_parse():
    # Create the arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input',
                        help='input amiibo dump to write')
    parser.add_argument('-uk', '--unfixed_info',
                        type=argparse.FileType('rb'),
                        default='keys/unfixed-info.bin',
                        help='unfixed info bin path')
    parser.add_argument('-lk', '--locked_key',
                        type=argparse.FileType('rb'),
                        default='keys/locked-secret.bin',
                        help='locked secret bin path')
    parser.add_argument('-o', '--output',
                        help='output file for the amiibo')
    parser.add_argument('-u', '--uid',
                        help='uuid of the key (ex: 04a01fe2a86480)')
    parser.add_argument('-w', '--write',
                        action='store_true',
                        help='Write the amiibo to the tag')
    parser.add_argument('-r', '--read',
                        action='store_true',
                        help='Read amiibo to the tag')
    parser.add_argument('-d', '--details',
                        action='store_true',
                        help='Get the amiibo info')
    parser.add_argument('-s', '--show_image',
                        action='store_true',
                        help='Show the Amiibo image (requires ueberzug)')
    parser.add_argument('-p', '--password',
                        action='store_true',
                        help='Print the password for the tag')
    parser.add_argument('--device',
                        default='usb',
                        help='The identifier of the nfc reader as nfcpy spec')
    parser.add_argument('--max_retry',
                        type=int,
                        help='Max number of write error before aborting')
    parser.add_argument('-v', '--verbose',
                        action='store_true',
                        help='Be verbose')
    args = parser.parse_args()
    # check constrains
    if args.write and not args.input:
        print_error("Input file is needed if you want to write")
        sys.exit(EXIT_FAILURE)
    return args


if __name__ == '__main__':
    args = arg_parse()
    device = args.device
    VERBOSE = args.verbose

    uid = args.uid
    if not uid:
        print_info("No uid provided, using the one from the card")
        tag = get_tag()
        if not tag:
            print_error("No tag found, exiting")
            sys.exit(1)
        uid = binascii.hexlify(tag.identifier).decode('utf-8')
        print_info("Found card with uid: " + uid)

    if args.password:
        print_info("The password for the TAG: " + calc_password(uid))
        if not args.write and not args.read:
            sys.exit(EXIT_SUCCESS)

    amiibo_data = bytes()
    if args.write:
        try:
            with open(args.input, 'rb') as input_amiibo:
                amiibo_data = input_amiibo.read()
        except IOError:
            print_error("Input file is not readable or does not exit")
            sys.exit(EXIT_FAILURE)
    elif args.read:
        print_info("Reading from the tag: " + uid)
        amiibo_data = read_from_tag()

    amiibo = make_new_amiibo(args.unfixed_info,
                             args.locked_key,
                             amiibo_data,
                             uid)

    if args.details:
        print_info("Getting character information, this might take a while")
        print_amiibo_details(amiibo.data, args.show_image)

    if args.read and not args.output:
        sys.exit(EXIT_SUCCESS)

    if args.output:
        print_info("Saving amiibo to {}".format(args.output))
        with open(args.output, 'wb') as of:
            of.write(amiibo.data)

    if args.write:
        print_info("Writing to the tag: " + uid)
        write_to_tag(tag, amiibo.data, args.max_retry)
