Overview
ShellyPng is a versatile Python tool designed to generate various types of reverse and bind shell payloads, apply multiple layers of obfuscation, and optionally embed these payloads within PNG images using Least Significant Bit (LSB) steganography. It includes a companion C2 server and automatically generates a standalone Python script to extract and execute embedded payloads on the target machine.

Features (In Depth)
Dual Operational Modes:

stego Mode: The primary mode for embedding payloads within images. Takes a source image, injects the obfuscated payload using LSB steganography, and saves the result as a new image file. It also generates a corresponding Python extractor script (extract_*.py).
generate Mode: Creates the selected payload, applies the chosen obfuscation level, but does not embed it in an image. Instead, it outputs the obfuscated payload (usually Base64 encoded) along with guidance and example code snippets (Python, PowerShell, etc.) demonstrating how to deobfuscate and execute it manually on a target system.
Diverse Payload Generation:

Leverages a dedicated PayloadGenerator class to create a wide range of shell payloads tailored for different operating systems and environments.
Supports common reverse shells (target connects back to listener) and bind shells (target listens for incoming connection).
Includes variations using different tools and techniques (e.g., bash, nc, mkfifo). (See full list under Payload Types below).
Polymorphic Obfuscation Engine:

Employs an Obfuscator class to apply various techniques, making the payload harder to detect by signature-based analysis.
Techniques: Includes Base64 encoding (multi-layer option), XOR encryption with random keys, Zlib compression, Hex encoding, and RC4 stream cipher encryption with random keys.
Configurable Levels:
Level 0: No obfuscation.
Level 1 (Basic): Applies a single obfuscation technique chosen randomly from the available options.
Level 2 (Advanced): Applies multiple, randomly selected techniques layered in a random order for increased complexity.
Automatic Deobfuscation Logic: When generating the extractor script or guidance, the tool automatically constructs the corresponding Python or PowerShell code required to reverse the applied obfuscation steps in the correct order.
LSB Steganography Implementation (stego mode):

Uses the StegoEngine class and relies on the Pillow library for image manipulation.
Hides data within the Least Significant Bits (LSBs) of the image's pixel color channels (Red, Green, Blue, and optionally Alpha).
Configurable Depth: Allows specifying how many bits per color channel to use (-b/--bits, 1-8), trading off capacity vs. potential visual distortion. Higher bit depth means more storage but higher chance of noticeable changes.
Alpha Channel Support: Can optionally utilize the alpha (transparency) channel for embedding if the image format supports it (-a/--alpha).
Metadata & EOM: Embeds the payload size at the beginning and uses a specific End-Of-Message (EOM) byte marker (\xDE\xC0\xAD\xDE) to signal the end of the hidden data during extraction.
Built-in C2 Server (-s/--server):

Provides a simple, multi-threaded TCP server to listen for incoming reverse shell connections on the specified host and port (-L, -p).
Handles multiple connections simultaneously.
Displays the connecting client's IP address and provides an interactive command prompt to send commands to the target shell.
Attempts to gracefully handle connection errors and user termination (Ctrl+C).
Standalone Extractor Script Generation (stego mode):

Automatically creates a .py file designed to be run on the target machine alongside the stego image.
This script is self-contained (apart from needing Python 3 and potentially Pillow) and includes:
The necessary LSB extraction logic (copied from StegoEngine).
The specific deobfuscation code required for the payload embedded in the associated image.
Execution logic to run the final, deobfuscated payload (e.g., using exec() for Python, subprocess.Popen for shell commands or PowerShell).
Includes command-line arguments for flexibility: specifying the image path (-i), deobfuscating Base64 directly (-d), or extracting/deobfuscating without executing (-n).
User-Friendly Interface:

Interactive Mode: If the inquirer library is installed, provides a step-by-step guided menu with prompts for all configuration options. Falls back to basic text prompts if inquirer is unavailable.
Command-Line Mode: Offers a comprehensive set of CLI arguments via argparse for scripting and automation. Includes help messages (-h/--help).
Dependency Management & Feedback:

Checks for essential libraries (like Pillow) and optional ones (inquirer, colorama, tqdm) at startup, providing installation instructions if missing.
Uses colorama for colored terminal output, improving readability of logs, errors, and prompts.
Uses tqdm (if installed) to display progress bars during the potentially time-consuming LSB embedding/extraction processes.
Includes verbose (-v) and quiet (-q) modes to control the amount of output.
Dependencies
The following Python libraries are required or recommended:

Pillow (Required for stego mode): Image manipulation.
inquirer (Optional): Enhanced interactive UI.
colorama (Recommended): Colored terminal output.
tqdm (Optional): Progress bars.
Install them using pip:

Bash

pip install Pillow inquirer colorama tqdm
Installation
Clone the repository (if applicable):

Bash

git clone <your-repo-url>
cd shellypng
Or, simply download the shelly.py script.

Install dependencies:

Bash

# Recommended: Create and use a virtual environment
# python3 -m venv venv
# source venv/bin/activate  # On Linux/macOS
# .\venv\Scripts\activate   # On Windows

pip install Pillow inquirer colorama tqdm
Usage
ShellyPng can be run in interactive mode or via command-line arguments.

(Usage examples remain the same as the previous version)

(Payload Types, Obfuscation Levels, Ethical Use, License, Contributing sections remain the same)
