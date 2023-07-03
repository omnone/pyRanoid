# PyRanoid :lock: ![Tests](https://github.com/omnone/pyRanoid/workflows/Tests/badge.svg) ![CodeQL](https://github.com/omnone/pyRanoid/workflows/CodeQL/badge.svg)
**PyRanoid** is a Python program designed to provide advanced encryption and steganography capabilities for your files. It utilizes AES 256 encryption to securely encrypt your files and then employs steganography techniques to hide the encrypted data within an image. Currently tested with Python 3.9.

## Getting Started
<ol>
<li>Select the file you want to encrypt and choose the encryption options.</li>
<li>Provide an image file to serve as the cover image for steganography.</li>
<li>PyRanoid will encrypt your file (a copy of it) using AES 256 encryption and embed it within the selected image.</li>
<li>Save the resulting image, which now contains the encrypted data.</li>
<li>To retrieve the original file, use PyRanoid to extract and decrypt the data from the steganographic image.</li>
</ol>

<img src="screenshot.png" width="650" height="410">

## Requirements
<ul>
<li>Python 3.9 or higher</li>
<li>Dependencies (listed in the requirements.txt file)</li>
<li>OpenSSL</li>
</ul>

## Contributing
Contributions to PyRanoid are welcome! If you encounter any issues or have ideas for enhancements, please feel free to submit a pull request or create an issue in the project's repository.

## License
[MIT](https://choosealicense.com/licenses/mit/)
