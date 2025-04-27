# ShellyPng 

## Image Steganography Research Tool

ShellyPng is an advanced steganography research tool that allows embedding PowerShell payloads within PNG images using LSB (Least Significant Bit) steganography techniques. This makes payloads virtually undetectable to casual observation and basic scanning tools.

## LEGAL DISCLAIMER 

ShellyPng is designed for **educational and research purposes ONLY**. The authors and contributors are NOT responsible for any misuse or damage caused by this program.

By using this software, you agree to use it responsibly and ethically. Always obtain proper authorization before testing on any systems.

**This tool should only be used in controlled environments with proper authorization.**

## Features

- Embeds PowerShell reverse shell payloads into PNG images using LSB steganography
- Generates obfuscated extraction commands for payload retrieval
- Built-in C2 server for receiving connections
- Interactive command-line interface
- Polymorphic payload generation for enhanced evasion
- Both interactive and CLI operation modes

## Why PNG Only?

ShellyPng specifically targets PNG files because:

1. **Lossless compression**: PNG uses lossless compression, ensuring that the embedded data remains intact after saving. Other formats like JPEG use lossy compression which can destroy the hidden data.

2. **Bit-level predictability**: PNG's format allows for precise manipulation of pixel data at the bit level, crucial for reliable LSB steganography.

3. **Metadata preservation**: When PNG images are uploaded to many websites and platforms, they often maintain their exact binary structure, preserving the steganographic payload. This persistence across platforms makes PNG an ideal carrier format.

4. **Alpha channel support**: PNG's support for transparency provides additional data channels that can be leveraged for payload hiding.

## Installation

```bash
# Clone the repository
git clone https://github.com/ash/shellypng
cd shellypng

# Install required dependencies
pip install colorama inquirer tqdm pillow
```

## Usage

### Interactive Mode

Simply run the script without any arguments:

```bash
python shelly.py
```

### Command-Line Mode

```bash
python shelly.py -H <C2_HOST> -p <C2_PORT> -i <INPUT_IMAGE> -o <OUTPUT_IMAGE> -s
```

#### Parameters

| Parameter | Description |
|-----------|-------------|
| `-H, --host` | C2 callback address (IP/hostname that target will connect back to) |
| `-p, --port` | C2 server port (default: 45913) |
| `-i, --image` | Input image path (default: decoy_image.png) |
| `-o, --output` | Output image path (default: output_image.png) |
| `-s, --server` | Start C2 server immediately |
| `-v, --verbose` | Enable verbose output |
| `-q, --quiet` | Suppress banner and disclaimer |
| `-c, --command-only` | Only output the extraction command |
| `-l, --listen` | Listen address for C2 server (default: 0.0.0.0) |

## Configuration Flexibility

ShellyPng is designed with flexibility in mind:

- **Customizable C2 Host**: You can specify any IP address or hostname for the callback.
- **Configurable Port**: The default port (45913) can be changed to any valid port number.
- **Input/Output Images**: Both source and destination image paths are fully configurable.
- **Listen Interface**: By default, the C2 server listens on all interfaces (0.0.0.0), but this can be configured.

This flexibility allows you to adapt the tool to various network environments and operational requirements.

## Known Issues

- When using the interactive prompt, there may be display issues when editing default values. The cursor may repeat previous characters when backspacing (showing as `[?] C2 callback address: 0.0.[?] C2 callback address: 0.0.`). This is a minor UI issue that doesn't affect functionality.

## Real-World Persistence

One of the notable aspects of PNG-based steganography is its resilience across many platforms. Unlike other file formats, PNG images often remain bit-for-bit identical when uploaded to various websites and services. This means:

- A steganographic payload embedded in a PNG image may remain intact even after the image is uploaded to social media or file-sharing sites
- The extraction command will continue to work as long as the PNG file is downloaded without modifications
- This creates unique research opportunities for studying how different platforms process and store image data

However, note that some platforms do recompress or modify uploaded images, which could potentially destroy the hidden payload.

## Advanced Usage

For penetration testing and security research in authorized environments, consider these advanced techniques:

- Use images that blend naturally with the target environment
- Combine with other evasion techniques for multi-layered approaches
- Customize the PowerShell payload for specific operational requirements

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
