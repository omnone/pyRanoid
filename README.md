# PyRanoid :lock: ![Tests](https://github.com/omnone/pyRanoid/workflows/Tests/badge.svg) ![CodeQL](https://github.com/omnone/pyRanoid/workflows/CodeQL/badge.svg)
**PyRanoid** allows you to **encrypt your data** , text or even a file, using [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) encryption and then to encode it/hide it to an PNG image using an lsb [steganography](https://en.wikipedia.org/wiki/Steganography) algorithm. If you feel extra paranoid you can add some RSA encryption on top. Currently RSA encryption is only supported throught the GUI version. Currently tested only with Python 3.9.

<img src="screenshot.png" width="750" height="510">

## Notes
1. There is no low-level memory management in Python, hence it is not possible to wipe memory areas were sensitive information was stored.
2. This project is still a proof of concept , so bugs may exist. If you find anything don't hasitate to open an issue.

## Installation

1. Clone the repository to any folder.

```
git clone https://github.com/omnone/pyRanoid/
```

2. Change directory into pyRanoid root folder.

```
cd ./pyRanoid
```

3. Install Python requirements

```
pip install -r requirements.txt
```

## Usage
TBD

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[MIT](https://choosealicense.com/licenses/mit/)
