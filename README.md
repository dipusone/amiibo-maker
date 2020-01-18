# Amiibo Maker

Full python3 implementation of an nfc amiibo dumper and writer.


### Prerequisites

The projects builds on three main libraries:
- [pyamiibo](https://github.com/tobywf/pyamiibo): ma make the amiibo
- [nfcpy](https://github.com/nfcpy/nfcpy): to write to a tag
- [ueberzug](https://github.com/seebye/ueberzug): to show the amiibo image in the terminal

The last one is optional.

To install the dependencies:

```bash
pip install -r requirements.txt
```

For the optional dependencies:

```bash
pip install -r requirements_optional.txt
```

You will need the key files used in the Amiibo encryption, which I cannot share.


### Usage

To dump an amiibo

``` bash
make_amiibo.py -r -o amiibo.bin
```


To write an amiibo:

```bash
make_amiibo.py -w -i amiibo.bin
```


There is also the option to retrieve amiibo information while reading/writing (as the character). The image preview will wait for confirmation to continue.

```bash
write_amiibo.py -w -i amiibo --details --show_image
```

You can get the full list of options with

```bash
write_amiibo.py -h
```
