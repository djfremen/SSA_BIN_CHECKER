import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import serial
import serial.tools.list_ports
import threading
import time
import struct
import os
import sys
import binascii
import datetime # Added for timestamp in log file name
import sv_ttk # Import the theme library
import pyperclip # For copying results
import re # For VIN regex

# --- Configuration ---
# TODO: Replace these placeholder templates with actual byte values found in cardwriter.exe
# Template format: [N, M, Byte2, Byte3, ..., ByteN+1]
# N = Send Payload Length (excluding checksum)
# M = Expected Response Payload Length (excluding checksum)
# Full Sent Packet = Template[2:N+2] + AddressBytes(if needed) + Checksum (Total N+1 bytes)
# Full Received Packet = ResponsePayload (M bytes) + Checksum (1 byte) (Total M+1 bytes)

# Tech2 Initialization/Restart Commands (from new workflow)
INIT_BAUD = 19200
CMD_DOWNLOAD = bytes([0xEF, 0x56, 0x80, 0x3B])
RESP_DOWNLOAD_OK = bytes([0xEF, 0x56, 0x01, 0xBA])
CMD_RESTART = bytes([0x8B, 0x56, 0x00, 0x1F])
INIT_STABILIZE_DELAY = 1 # seconds
INIT_CMD_DELAY = 2 # seconds
INIT_RESPONSE_TIMEOUT = 8 # seconds

# Tech2 Read Chunk Commands (from web app)
CHUNK_COMMANDS = [
    bytes([0x81, 0x5A, 0x0F, 0x2E, 0x00, 0x00, 0xA6, 0x42]),  # Offset: 0x00
    bytes([0x81, 0x5A, 0x0F, 0x2E, 0x00, 0xA6, 0xA6, 0x9C]),  # Offset: 0xA6
    bytes([0x81, 0x5A, 0x0F, 0x2E, 0x01, 0x4C, 0xA6, 0xF5]),  # Offset: 0x14C
    bytes([0x81, 0x5A, 0x0F, 0x2E, 0x01, 0xF2, 0xA6, 0x4F]),  # Offset: 0x1F2
    bytes([0x81, 0x5A, 0x0F, 0x2E, 0x02, 0x98, 0x32, 0x1C])   # Offset: 0x298
]
CHUNK_SIZES = [169, 169, 169, 169, 53]

# Data Transfer Commands (from cardwriter.exe analysis)
# TODO: Replace these placeholder templates with actual byte values found in cardwriter.exe
# Template format: [N, M, Byte2, Byte3, ..., ByteN+1]
HANDSHAKE_BAUD = 19200
READ_BAUD = 115200
# Command 1: Initiate Handshake? (Example Placeholder)
CMD1_DATA = bytes([0x05, 0x03, 0xF0, 0x01, 0x00, 0x00, 0x00]) # N=5, M=3, Payload=[F0, 01, 00, 00, 00]
# Command 3: Baud Rate Acknowledge / Switch? (Example Placeholder)
CMD3_DATA = bytes([0x05, 0x03, 0xF0, 0x03, 0x00, 0x00, 0x00]) # N=5, M=3, Payload=[F0, 03, 00, 00, 00]
# Command 7: Read Data Request (Example Placeholder)
CMD7_DATA = bytes([0x07, 0x83, 0xF1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]) # N=7, M=0x83 (131) Payload=[F1, Addr1, Addr2, 00, 00, 00, 00]

# --- Derived Constants ---
N1 = CMD1_DATA[0]
M1 = CMD1_DATA[1]
CMD1_PAYLOAD = CMD1_DATA[2 : N1 + 2]

N3 = CMD3_DATA[0]
M3 = CMD3_DATA[1]
CMD3_PAYLOAD = CMD3_DATA[2 : N3 + 2]

N7 = CMD7_DATA[0]
M7 = CMD7_DATA[1] # Expected response payload length (e.g., 131 bytes = 3 status + 128 data)
CMD7_BASE_PAYLOAD = bytearray(CMD7_DATA[2 : N7 + 2]) # Mutable for address injection

# Assuming Response Structure for Cmd 7: [Status1, Status2, Status3=0xAA, Data(128 bytes)] + Checksum
# M7 should be 3 + 128 = 131. Check CMD7_DATA[1] value.
EXPECTED_RESPONSE_STATUS_BYTE_INDEX = 2 # Index of the 0xAA byte
EXPECTED_RESPONSE_STATUS_BYTE_VALUE = 0xAA
PAYLOAD_START_INDEX = 3
READ_CHUNK_SIZE = max(0, M7 - PAYLOAD_START_INDEX) # e.g., 131 - 3 = 128 bytes

TOTAL_SIZE = 0x2000000 # 32MB
SERIAL_TIMEOUT = 2 # Default seconds for data transfer reads
# Use INIT_RESPONSE_TIMEOUT for the initial download mode response

OUTPUT_FILENAME = "tech2_flash.bin"

# --- Helper Functions ---

def hex_dump(data):
    """Convert binary data to a readable hex format"""
    if isinstance(data, bytes) or isinstance(data, bytearray):
        hex_data = binascii.hexlify(data).decode('ascii')
    else:
        hex_data = binascii.hexlify(bytes(data)).decode('ascii')
    return ' '.join([hex_data[i:i+2] for i in range(0, len(hex_data), 2)])

# --- OS-level Port Access Functions ---

def os_open_port(port_name):
    """Open the port using low-level OS calls."""
    try:
        # Format port name for the platform
        if sys.platform == 'win32':
            port_path = f"\\\\.\\{port_name}"
        else:
            port_path = port_name
            
        # Open in binary mode
        binary_flag = os.O_BINARY if hasattr(os, 'O_BINARY') else 0
        port_fd = os.open(port_path, os.O_RDWR | binary_flag)
        
        return port_fd
    except Exception as e:
        raise ValueError(f"Error opening port {port_name}: {e}")

def os_close_port(port_fd):
    """Close the port using low-level OS calls."""
    if port_fd is not None:
        try:
            os.close(port_fd)
            return True
        except Exception as e:
            print(f"Error closing port: {e}")
    return False

def os_send_command(port_fd, command, description="command"):
    """Send a command to the device using low-level OS calls."""
    try:
        bytes_written = os.write(port_fd, command)
        return bytes_written == len(command)
    except Exception as e:
        raise ValueError(f"Error sending {description}: {e}")

def os_read_response(port_fd, expected_length, timeout=5, description="response", cancel_check_func=None):
    """Read response from device with timeout using low-level OS calls. Non-blocking approach."""
    try:
        response = bytearray()
        start_time = time.time()
        
        # Don't block waiting for data, actively poll
        poll_interval = 0.05  # Check more frequently (50ms)
        
        while len(response) < expected_length:
            # Check for cancellation FREQUENTLY
            if cancel_check_func and cancel_check_func():
                print(f"Read operation cancelled during {description}")
                return response
                
            # Check for timeout
            elapsed = time.time() - start_time
            if elapsed > timeout:
                print(f"Timeout after {elapsed:.1f}s waiting for {description}")
                return response  # Return whatever we got so far
            
            try:
                # Try to read just a single byte at a time - non-blocking approach
                try_read_size = 1
                try:
                    # This will quickly return with either data or an error if nothing available
                    chunk = os.read(port_fd, try_read_size)
                    
                    if chunk:
                        response.extend(chunk)
                        print(f"Read 1 byte, total: {len(response)}/{expected_length}")
                    # No explicit else - if no data was available, we'll just check again
                except BlockingIOError:
                    # This is expected when no data is available
                    pass
                except OSError as e:
                    # Many OSErrors are expected when reading with no data available
                    # Just log if it's something unexpected (not error 11 EAGAIN)
                    if hasattr(e, 'errno') and e.errno != 11:
                        print(f"OSError during read: {e}")
                
            except Exception as e:
                print(f"Unexpected error during read: {e}")
                
            # Always sleep briefly to avoid CPU spinning and allow cancellation
            time.sleep(poll_interval)
        
        return response
            
    except Exception as e:
        raise ValueError(f"Error reading {description}: {e}")

def os_enter_download_mode(port_name, log_func=print, cancel_check_func=None):
    """Attempt to enter download mode using OS-level port functions. Returns port_fd on success, None on failure."""
    port_fd = None
    try:
        log_func(f"Opening {port_name} using OS-level access...")
        port_fd = os_open_port(port_name)
        
        # On Windows, try to set the correct serial parameters
        if sys.platform == 'win32':
            try:
                import ctypes
                import ctypes.wintypes
                
                # Windows DCB (Device Control Block) structure for serial port settings
                class DCB(ctypes.Structure):
                    _fields_ = [
                        ("DCBlength", ctypes.wintypes.DWORD),
                        ("BaudRate", ctypes.wintypes.DWORD),
                        ("fBinary", ctypes.wintypes.DWORD, 1),
                        ("fParity", ctypes.wintypes.DWORD, 1),
                        ("fOutxCtsFlow", ctypes.wintypes.DWORD, 1),
                        ("fOutxDsrFlow", ctypes.wintypes.DWORD, 1),
                        ("fDtrControl", ctypes.wintypes.DWORD, 2),
                        ("fDsrSensitivity", ctypes.wintypes.DWORD, 1),
                        ("fTXContinueOnXoff", ctypes.wintypes.DWORD, 1),
                        ("fOutX", ctypes.wintypes.DWORD, 1),
                        ("fInX", ctypes.wintypes.DWORD, 1),
                        ("fErrorChar", ctypes.wintypes.DWORD, 1),
                        ("fNull", ctypes.wintypes.DWORD, 1),
                        ("fRtsControl", ctypes.wintypes.DWORD, 2),
                        ("fAbortOnError", ctypes.wintypes.DWORD, 1),
                        ("fDummy2", ctypes.wintypes.DWORD, 17),
                        ("wReserved", ctypes.wintypes.WORD),
                        ("XonLim", ctypes.wintypes.WORD),
                        ("XoffLim", ctypes.wintypes.WORD),
                        ("ByteSize", ctypes.wintypes.BYTE),
                        ("Parity", ctypes.wintypes.BYTE),
                        ("StopBits", ctypes.wintypes.BYTE),
                        ("XonChar", ctypes.c_char),
                        ("XoffChar", ctypes.c_char),
                        ("ErrorChar", ctypes.c_char),
                        ("EofChar", ctypes.c_char),
                        ("EvtChar", ctypes.c_char),
                        ("wReserved1", ctypes.wintypes.WORD),
                    ]
                
                # Windows constants for serial port settings
                EVEN_PARITY = 2
                TWO_STOPBITS = 2
                RTS_CONTROL_HANDSHAKE = 2
                
                # Get DCB structure for the port
                dcb = DCB()
                dcb.DCBlength = ctypes.sizeof(DCB)
                
                GetCommState = ctypes.windll.kernel32.GetCommState
                GetCommState.argtypes = [ctypes.wintypes.HANDLE, ctypes.POINTER(DCB)]
                GetCommState.restype = ctypes.wintypes.BOOL
                
                SetCommState = ctypes.windll.kernel32.SetCommState
                SetCommState.argtypes = [ctypes.wintypes.HANDLE, ctypes.POINTER(DCB)]
                SetCommState.restype = ctypes.wintypes.BOOL
                
                if GetCommState(port_fd, ctypes.byref(dcb)):
                    # Set serial port parameters
                    dcb.BaudRate = INIT_BAUD
                    dcb.ByteSize = 8
                    dcb.Parity = EVEN_PARITY  # Even parity
                    dcb.StopBits = TWO_STOPBITS  # 2 stop bits
                    dcb.fRtsControl = RTS_CONTROL_HANDSHAKE  # Hardware flow control
                    dcb.fParity = 1  # Enable parity checking
                    
                    if SetCommState(port_fd, ctypes.byref(dcb)):
                        log_func("Serial port parameters set: 19200 baud, 8E2, HW flow control")
                    else:
                        log_func("Warning: Failed to set serial port parameters")
                else:
                    log_func("Warning: Failed to get current serial port state")
                    
            except Exception as e:
                log_func(f"Warning: Could not set Windows-specific serial port parameters: {e}")
        
        log_func(f"Port opened. Waiting {INIT_STABILIZE_DELAY}s for stabilization...")
        time.sleep(INIT_STABILIZE_DELAY)
        
        # Check for early cancellation
        if cancel_check_func and cancel_check_func():
            log_func("Operation cancelled before sending commands")
            os_close_port(port_fd)
            return None
        
        # Send first command
        log_func(f"Sending Download Cmd 1/2: {hex_dump(CMD_DOWNLOAD)}")
        if not os_send_command(port_fd, CMD_DOWNLOAD, "download command 1"):
            log_func("Failed to send first download command")
            os_close_port(port_fd)
            return None
            
        log_func(f"Waiting {INIT_CMD_DELAY}s...")
        time.sleep(INIT_CMD_DELAY)
        
        # Check for cancellation after first command
        if cancel_check_func and cancel_check_func():
            log_func("Operation cancelled after first command")
            os_close_port(port_fd)
            return None
        
        # Send second command
        log_func(f"Sending Download Cmd 2/2: {hex_dump(CMD_DOWNLOAD)}")
        if not os_send_command(port_fd, CMD_DOWNLOAD, "download command 2"):
            log_func("Failed to send second download command")
            os_close_port(port_fd)
            return None
        
        # Read verification response
        log_func(f"Waiting for response ({INIT_RESPONSE_TIMEOUT}s timeout): {hex_dump(RESP_DOWNLOAD_OK)}")
        response = os_read_response(port_fd, len(RESP_DOWNLOAD_OK), INIT_RESPONSE_TIMEOUT, 
                                   "download mode verification", cancel_check_func)
        
        # Check if operation was cancelled during read
        if cancel_check_func and cancel_check_func():
            log_func("Operation cancelled while waiting for response")
            os_close_port(port_fd)
            return None
        
        if not response:
            log_func("No response received")
            os_close_port(port_fd)
            return None
            
        log_func(f"Received response: {hex_dump(response)}")
        
        if response == RESP_DOWNLOAD_OK:
            log_func("Download Mode Entered Successfully!")
            return port_fd
        else:
            log_func(f"Unexpected response, expected: {hex_dump(RESP_DOWNLOAD_OK)}")
            os_close_port(port_fd)
            return None
            
    except Exception as e:
        log_func(f"Error entering download mode: {e}")
        if port_fd is not None:
            os_close_port(port_fd)
        return None

def os_restart_tech2(port_fd=None, port_name=None, log_func=print):
    """Send restart command using OS-level functions. If port_fd is None, tries to open port_name."""
    need_to_close = False
    try:
        if port_fd is None and port_name:
            log_func(f"Opening {port_name} for restart...")
            port_fd = os_open_port(port_name)
            need_to_close = True
            
        if port_fd is None:
            log_func("No valid port handle for restart")
            return False
            
        log_func(f"Sending Restart Cmd: {hex_dump(CMD_RESTART)}")
        result = os_send_command(port_fd, CMD_RESTART, "restart command")
        # Log the result of the OS-level send
        log_func(f"os_send_command for restart returned: {result}") 
        time.sleep(0.1) # Short delay to ensure send completes
        
        if result:
            log_func("Restart command sent successfully")
        else:
            log_func("Failed to send restart command")
            
        return result
        
    except Exception as e:
        log_func(f"Error sending restart command: {e}")
        return False
    finally:
        if need_to_close and port_fd is not None:
            os_close_port(port_fd)
            log_func("Port closed after restart command")

# --- Protocol Functions for Reading Flash ---

def calculate_checksum(data):
    """Calculates the checksum used by the protocol."""
    checksum = 0
    for byte in data:
        checksum -= byte
    return checksum & 0xFF

def create_read_packet(address):
    """Creates the command 7 packet with the specified address."""
    if READ_CHUNK_SIZE == 0:
        # This happens if CMD7_DATA template is likely wrong (M7 too small)
        raise ValueError("READ_CHUNK_SIZE is 0. Check CMD7_DATA template (byte 1).")

    packet = CMD7_BASE_PAYLOAD[:] # Create a copy

    # Inject address bytes based on analysis of StartAddress loop (lines 5027-5028)
    # Note: This differs from sub_401E9C used for writing. Verify this logic.
    packet[1] = (address >> 20) & 0xFF # Assuming offset 1 in payload (index 3 in buffer)
    packet[2] = ((address >> 17) & 0x07) # Assuming offset 2 in payload (index 4 in buffer)

    checksum = calculate_checksum(packet)
    return bytes(packet) + bytes([checksum])

def send_command_read_response(ser, command_payload, expected_response_len, description, read_timeout=SERIAL_TIMEOUT):
    """Sends a command (payload + checksum) and waits for a response, validating checksum."""
    packet = bytes(command_payload) + bytes([calculate_checksum(command_payload)])
    log(f"Sending {description} ({len(packet)} bytes): {hex_dump(packet)}")
    ser.reset_input_buffer()
    ser.reset_output_buffer()
    ser.write(packet)
    time.sleep(0.05) # Short delay after sending

    # Read response (payload + checksum)
    response_len = expected_response_len + 1
    log(f"Expecting {response_len} bytes response (timeout: {read_timeout}s)...")
    ser.timeout = read_timeout # Use specific timeout for this read
    response = ser.read(response_len)
    ser.timeout = SERIAL_TIMEOUT # Restore default timeout

    if len(response) != response_len:
        raise TimeoutError(f"Timeout waiting for {description} response. Got {len(response)}/{response_len} bytes.")

    log(f"Received {description} response ({len(response)} bytes): {hex_dump(response)}")

    # Validate checksum
    received_payload = response[:-1]
    received_checksum = response[-1]
    calculated_checksum = calculate_checksum(received_payload)

    if received_checksum != calculated_checksum:
        raise ValueError(f"Checksum mismatch for {description}. Got {received_checksum:02X}, expected {calculated_checksum:02X}")

    return received_payload # Return only the payload part

# --- Main Application Class ---

class Tech2ReaderApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Tech2 Reader & Analyzer") # Updated title
        self.serial_port = None # pySerial port object
        self.os_port_fd = None  # OS-level file descriptor for raw port access
        self.is_busy = False
        self.download_mode_active = False
        self.cancel_requested = False  # Flag to indicate user requested cancel
        self.worker_thread = None  # Reference to current worker thread
        self.force_exit = False   # Flag for complete application shutdown

        # --- Apply the theme ---
        sv_ttk.set_theme("dark") # Or "light"
        
        # Make the app more responsive to DPI settings if possible
        try:
            from ctypes import windll
            windll.shcore.SetProcessDpiAwareness(1)
            # Set AppUserModelID for distinct taskbar icon (optional)
            windll.shell32.SetCurrentProcessExplicitAppUserModelID("Tech2ReaderAnalyzer.App")
        except Exception:
            pass

        # UI Elements
        frame = ttk.Frame(root, padding="10")
        frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Port Selection
        port_frame = ttk.LabelFrame(frame, text="Serial Port", padding=5)
        port_frame.grid(row=0, column=0, columnspan=3, sticky=(tk.W, tk.E), padx=5, pady=5)
        ttk.Label(port_frame, text="COM Port:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.port_var = tk.StringVar()
        self.port_combo = ttk.Combobox(port_frame, textvariable=self.port_var, width=25)
        self.port_combo.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5, pady=2)
        self.refresh_button = ttk.Button(port_frame, text="Refresh", command=self.refresh_ports)
        self.refresh_button.grid(row=0, column=2, sticky=tk.W, padx=5, pady=2)
        port_frame.columnconfigure(1, weight=1)

        # Control Buttons
        button_frame = ttk.Frame(frame, padding=5)
        button_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), padx=5, pady=5)

        self.init_button = ttk.Button(button_frame, text="Enter Download Mode", command=self.start_init_download_mode)
        self.init_button.grid(row=0, column=0, padx=5, pady=5)

        self.download_button = ttk.Button(button_frame, text="Download Flash", command=self.start_flash_download, state=tk.DISABLED)
        self.download_button.grid(row=0, column=1, padx=5, pady=5)

        self.restart_button = ttk.Button(button_frame, text="Restart Tech2", command=self.start_restart_tech2)
        self.restart_button.grid(row=0, column=2, padx=5, pady=5)
        
        # Button row 2
        button_row2 = ttk.Frame(button_frame)
        button_row2.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), padx=5, pady=5)
        
        # SSA Read Button
        self.ssa_button = ttk.Button(button_row2, text="Read SSA", command=self.start_ssa_download)
        self.ssa_button.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Analyze SSA Button (New)
        self.analyze_ssa_button = ttk.Button(button_row2, text="Analyze SSA File", command=self.analyze_ssa_file)
        self.analyze_ssa_button.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Cancel Button
        self.cancel_button = ttk.Button(button_row2, text="Cancel Operation", command=self.cancel_operation, state=tk.DISABLED)
        self.cancel_button.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Force Close Button - always available
        self.force_close_button = ttk.Button(button_row2, text="Force Close App", command=self.force_close_app, style="Accent.TButton")
        self.force_close_button.pack(side=tk.RIGHT, padx=5)

        # Log Area
        log_frame = ttk.LabelFrame(frame, text="Log", padding=5)
        log_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5, pady=5)
        self.log_area = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, width=60, height=15)
        self.log_area.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.log_area.configure(state='disabled') # Read-only
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

        # --- Analysis Results Area (New) ---
        analysis_frame = ttk.LabelFrame(frame, text="VIN Analysis Results", padding=5)
        analysis_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5, pady=5)
        
        self.analysis_area = scrolledtext.ScrolledText(analysis_frame, wrap=tk.WORD, width=80, height=10, font=("Consolas", 10))
        self.analysis_area.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.analysis_area.configure(state='disabled') # Read-only
        
        # Add right-click menu for copying from analysis area
        self.create_analysis_context_menu()

        analysis_frame.columnconfigure(0, weight=1)
        analysis_frame.rowconfigure(0, weight=1)
        # --- End Analysis Results Area ---

        # Progress Bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(frame, variable=self.progress_var, maximum=100)
        self.progress_bar.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), padx=5, pady=10) # Adjusted row

        # Configure resizing
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1) # Main frame row
        frame.columnconfigure(0, weight=1)
        # Adjust row weights for the new layout
        frame.rowconfigure(2, weight=1) # Log area row
        frame.rowconfigure(3, weight=1) # Analysis area row
        frame.rowconfigure(4, weight=0) # Progress bar row

        # Add periodic check for force exit
        self.check_force_exit()
        
        self.refresh_ports()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing) # Handle window close

    def check_force_exit(self):
        """Periodically check if force exit is requested"""
        if self.force_exit:
            self.root.destroy()
        else:
            # Check again in 100ms
            self.root.after(100, self.check_force_exit)
            
    def force_close_app(self):
        """Force close the application, terminating any operations"""
        if self.is_busy:
            result = messagebox.askquestion("Force Close", 
                         "Are you sure you want to force close the application?\nThis may leave the Tech2 in an undefined state.",
                         icon='warning')
            if result != 'yes':
                return
                
        self.log("Force closing application...")
        self.cancel_requested = True
        self.force_exit = True
        self.cleanup_ports()
        
        # Don't wait for thread completion if force closing
        self.root.destroy()

    def log(self, message):
        """Add message to the log text area"""
        if self.force_exit:
            return # Don't try to log if we're force closing
            
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        def update_log_area():
            try:
                if self.log_area.winfo_exists(): # Check if widget still exists
                    self.log_area.configure(state='normal')
                    self.log_area.insert(tk.END, log_entry)
                    self.log_area.configure(state='disabled')
                    self.log_area.see(tk.END)
            except tk.TclError as e:
                # Handle cases where the widget might be destroyed during shutdown
                print(f"Log update error (likely during shutdown): {e}", file=sys.__stderr__)
            except Exception as e:
                 print(f"Unexpected log update error: {e}", file=sys.__stderr__)

        # Ensure UI updates happen on the main thread
        if hasattr(self.root, 'after'):
             self.root.after(0, update_log_area)
        else:
             # Fallback if root doesn't have 'after' (e.g., during very early init or late shutdown)
             print(log_entry, file=sys.__stderr__) 
        
        # Also print to the actual console/log file via redirected print
        print(log_entry.strip()) # strip newline as print adds one

    def update_progress(self, value):
         """Updates progress bar in a thread-safe way."""
         def _update():
             self.progress_var.set(value)
         if self.root.winfo_exists():
             self.root.after(0, _update)

    def refresh_ports(self):
        """Updates the COM port dropdown list."""
        if self.is_busy: return
        ports = [port.device for port in serial.tools.list_ports.comports()]
        self.port_combo['values'] = ports
        if ports:
            # Try to preserve selection, otherwise default to first
            current = self.port_var.get()
            if current not in ports:
                self.port_var.set(ports[0])
        else:
            self.port_var.set("")
        self.log("Refreshed COM ports.")

    def set_busy(self, busy_state):
        """Set the busy state and update UI elements accordingly."""
        self.is_busy = busy_state
        self.cancel_requested = False # Reset cancel flag when state changes
        
        # Enable/disable buttons based on state
        state = tk.DISABLED if busy_state else tk.NORMAL
        busy_text = "Cancel" if busy_state else "Cancel Operation"
        cancel_state = tk.NORMAL if busy_state else tk.DISABLED
        
        # Safely update UI elements
        try:
            if self.init_button.winfo_exists(): self.init_button.configure(state=state)
            if self.download_button.winfo_exists(): self.download_button.configure(state=state)
            # Keep restart button enabled even when busy
            # if self.restart_button.winfo_exists(): self.restart_button.configure(state=state) 
            if self.ssa_button.winfo_exists(): self.ssa_button.configure(state=state)
            if self.analyze_ssa_button.winfo_exists(): self.analyze_ssa_button.configure(state=state) # Also disable/enable this
            if self.cancel_button.winfo_exists(): self.cancel_button.configure(text=busy_text, command=self.cancel_operation, state=cancel_state)
            if self.refresh_button.winfo_exists(): self.refresh_button.configure(state=state)
            if self.port_combo.winfo_exists(): self.port_combo.configure(state=('readonly' if not busy_state else tk.DISABLED))
        except tk.TclError:
            self.log("Error updating UI state (window likely closing)")
            
        # Update progress bar state
        if not busy_state:
             self.root.after(100, lambda: self.progress_var.set(0))

    def start_threaded_task(self, target_func, args=()):
        """Starts a task in a thread and handles busy state."""
        if self.is_busy:
            self.log("Operation already in progress.")
            return False

        port = self.port_var.get()
        if not port and target_func != self.restart_tech2_thread : # Restart might work without port selected if already open
             if not self.serial_port and not self.os_port_fd:
                 messagebox.showerror("Error", "Please select a COM port.")
                 return False

        self.set_busy(True)
        self.progress_var.set(0)
        
        # Create the thread - pass only the args tuple provided by the caller
        # (Reverting this based on TypeError analysis)
        # self.worker_thread = threading.Thread(target=target_func, args=args, daemon=True)
        self.worker_thread = threading.Thread(target=target_func, args=(port,) + args, daemon=True)
        self.worker_thread.start()
        return True

    def start_init_download_mode(self):
        self.log("Attempting to enter download mode...")
        self.start_threaded_task(self.init_download_mode_thread)

    def start_flash_download(self):
        if not self.download_mode_active:
             messagebox.showerror("Error", "Please 'Enter Download Mode' first.")
             return
        self.log("Starting flash download process...")
        self.start_threaded_task(self.flash_download_thread)

    def start_ssa_download(self):
        """Start the SSA data download thread"""
        if not self.download_mode_active:
             messagebox.showerror("Error", "Please 'Enter Download Mode' first.")
             return
        self.log("Starting SSA data download...") # Simplified log message
        self.start_threaded_task(self.ssa_download_thread)

    def start_restart_tech2(self):
        if not self.download_mode_active: 
             messagebox.showerror("Error", "Restart command should be sent after 'Enter Download Mode' attempt (even if failed).")
        self.log("Attempting to restart Tech2...")
        # Pass the current port name
        port_name = self.port_var.get()
        # Port is automatically added by start_threaded_task
        self.start_threaded_task(self.restart_tech2_thread)

    def init_download_mode_thread(self, port_name):
        """Tries to put the Tech2 into download mode using OS-level port access."""
        global log # Make log function available for helper functions
        log = self.log
        
        try:
            # Close any existing connections
            self.cleanup_ports()
            
            # Define a cancellation check function that checks self.cancel_requested
            def check_cancel():
                if self.cancel_requested:
                    self.log("Download mode initialization cancelled by user")
                    return True
                return False
            
            # Use the OS-level function to enter download mode with cancellation check
            self.os_port_fd = os_enter_download_mode(port_name, self.log, check_cancel)
            
            if self.os_port_fd is not None:
                self.download_mode_active = True
            else:
                if not self.cancel_requested:  # Only log failure if not cancelled
                    self.log("Failed to enter download mode")
                self.download_mode_active = False
                
        except Exception as e:
            self.log(f"Error entering download mode: {e}")
            import traceback
            self.log(traceback.format_exc())
            self.download_mode_active = False
        finally:
            # Update the UI state
            self.root.after(0, self.set_busy, False)
            

    def restart_tech2_thread(self, port_name):
        """Sends the restart command using OS-level port access."""
        global log
        log = self.log
        
        try:
            result = False
            
            # Define cancellation check
            def check_cancel():
                if self.cancel_requested:
                    self.log("Restart operation cancelled by user")
                    return True
                return False
            
            # Check for early cancellation
            if check_cancel():
                return
            
            # Use existing OS port handle if it exists
            if self.os_port_fd is not None:
                self.log("Using existing OS port handle for restart")
                result = os_restart_tech2(port_fd=self.os_port_fd, log_func=self.log)
            # Otherwise, try to open a new connection
            else:
                self.log(f"Opening new connection to {port_name} for restart")
                result = os_restart_tech2(port_name=port_name, log_func=self.log)
                
            if result:
                self.log("Tech2 restart command sent successfully")
            else:
                self.log("Failed to send restart command")
                
        except Exception as e:
            self.log(f"Error sending restart command: {e}")
            import traceback
            self.log(traceback.format_exc())
        finally:
            # Add a small delay before cleanup, maybe needed for Tech2 to process restart
            self.log("Waiting briefly after restart command...")
            time.sleep(0.5) 
            # Always clean up and reset state
            self.cleanup_ports()
            self.download_mode_active = False
            self.root.after(0, self.set_busy, False)

    def cleanup_ports(self):
        """Close any open ports and reset connection state - safely handle any errors."""
        # Close OS file descriptor if open
        if self.os_port_fd is not None:
            try:
                self.log("Closing OS port handle...")
                try:
                    os_close_port(self.os_port_fd)
                    self.log("OS port handle closed")
                except Exception as e:
                    self.log(f"Error closing OS port: {e}")
                    
                # Even if the close fails, consider the handle invalid now
                self.os_port_fd = None
            except Exception as e:
                self.log(f"Unexpected error during OS port cleanup: {e}")
                self.os_port_fd = None
                
        # Close pySerial port if open
        if self.serial_port and hasattr(self.serial_port, 'is_open') and self.serial_port.is_open:
            try:
                self.log(f"Closing serial port {self.serial_port.port}...")
                try:
                    self.serial_port.close()
                    self.log("Serial port closed")
                except Exception as e:
                    self.log(f"Error closing serial port: {e}")
                    
                # Even if the close fails, consider the port invalid now
                self.serial_port = None
            except Exception as e:
                self.log(f"Unexpected error during pySerial port cleanup: {e}")
                self.serial_port = None

    def flash_download_thread(self, port_name):
        """Downloads the flash memory using the chunk commands from the web application with OS-level port access."""
        global log
        log = self.log
        
        try:
            if not self.download_mode_active or self.os_port_fd is None:
                raise ValueError("Not in download mode or no active port handle")
                
            # Check for early cancellation
            if self.cancel_requested:
                self.log("Flash download cancelled before starting")
                return
                
            # Keep using the OS-level port handle - DON'T CLOSE IT
            port_fd = self.os_port_fd
            self.log(f"Using existing OS port handle for download - no need to close/reopen")
            
            # Read data in chunks
            data_buffers = []
            expected_chunks = len(CHUNK_COMMANDS)
            self.log("Starting to read Tech2 data in chunks...")
            
            for i, (cmd, size) in enumerate(zip(CHUNK_COMMANDS, CHUNK_SIZES)):
                # Check for cancellation before each chunk
                if self.cancel_requested:
                    self.log(f"Flash download cancelled before reading chunk {i+1}")
                    break
                
                try:
                    self.log(f"Reading chunk {i+1}/{expected_chunks} (expected size: {size} bytes)")
                    
                    # Send the command
                    if not os_send_command(port_fd, cmd, f"chunk {i+1} command"):
                        raise ValueError(f"Failed to send command for chunk {i+1}")
                    
                    # Read the response with a longer timeout
                    response = os_read_response(port_fd, size, 15, f"chunk {i+1} data", 
                                              lambda: self.cancel_requested)
                    
                    # Accept partial chunks if we got at least half the data
                    min_acceptable = size // 2
                    if len(response) < min_acceptable:
                        self.log(f"Warning: Received insufficient data ({len(response)}/{size} bytes) for chunk {i+1}")
                        if len(response) == 0:
                            raise TimeoutError(f"No data received for chunk {i+1}")
                        
                    self.log(f"Received {len(response)}/{size} bytes for chunk {i+1}")
                    data_buffers.append(response)
                    
                    # Update progress
                    progress = ((i + 1) / expected_chunks) * 100
                    self.update_progress(progress)
                    
                    # Longer delay between chunks to let the Tech2 recover
                    time.sleep(0.5)
                    
                except Exception as e:
                    self.log(f"Error reading chunk {i+1}: {e}")
                    # Don't break - try getting the next chunk anyway
                    if len(response) > 0:
                        self.log(f"Saving partial data ({len(response)} bytes) for chunk {i+1}")
                        data_buffers.append(response)
                    else:
                        # Add empty buffer as placeholder
                        data_buffers.append(bytearray())
            
            # Check if we have any data to process
            if not data_buffers or all(len(buf) == 0 for buf in data_buffers):
                self.log("No data received from any chunks")
                return
            
            self.log(f"Processing {len(data_buffers)} data chunks (some may be incomplete)")
            
            # Calculate total size of the data (excluding headers)
            total_data_size = 0
            for i, buffer in enumerate(data_buffers):
                # Each chunk has a 2-byte header
                if len(buffer) > 2:
                    total_data_size += len(buffer) - 2
                elif len(buffer) > 0:
                    total_data_size += len(buffer)  # If very small, just keep all bytes
                
            # Combine all data, skipping headers where possible
            result_buffer = bytearray(total_data_size)
            offset = 0
            
            for i, buffer in enumerate(data_buffers):
                if len(buffer) == 0:
                    continue  # Skip empty buffers
                
                # Skip the first 2 bytes if we have enough data
                header_size = 2 if len(buffer) > 2 else 0
                data_size = len(buffer) - header_size
                
                if data_size > 0:
                    result_buffer[offset:offset+data_size] = buffer[header_size:header_size+data_size]
                    offset += data_size
            
            # Trim result buffer if we didn't fill it completely
            if offset < len(result_buffer):
                result_buffer = result_buffer[:offset]
            
            # Save the result
            if len(result_buffer) > 0:
                with open(OUTPUT_FILENAME, "wb") as outfile:
                    outfile.write(result_buffer)
                    
                self.log(f"Download complete! Saved {len(result_buffer) / 1024:.1f} KB to {OUTPUT_FILENAME}")
                
                # Also save raw data for analysis
                with open(OUTPUT_FILENAME + ".raw", "wb") as rawfile:
                    for i, buffer in enumerate(data_buffers):
                        if len(buffer) > 0:
                            rawfile.write(buffer)
                            
                self.log(f"Saved raw chunk data to {OUTPUT_FILENAME}.raw for analysis")
            else:
                self.log("No usable data extracted from the chunks")

        except Exception as e:
            self.log(f"Flash download failed: {e}")
            import traceback
            self.log(traceback.format_exc())
        finally:
            # Don't clean up ports here - keep the OS handle active
            # Just reset busy state
            self.root.after(0, self.set_busy, False)

    def ssa_download_thread(self, port_name):
        """Downloads the SSA data by reading the first 5 known chunks and combining them, similar to the web example."""
        global log
        log = self.log
        
        try:
            if not self.download_mode_active or self.os_port_fd is None:
                raise ValueError("Not in download mode or no active port handle")
                
            # Use existing OS-level port handle
            port_fd = self.os_port_fd
            self.log(f"Using existing OS port handle for SSA download")
            
            # These are the commands and sizes needed for SSA data, based on web example
            ssa_commands = CHUNK_COMMANDS[:5]
            ssa_sizes = CHUNK_SIZES[:5]
            expected_final_data_size = 714 # 166*4 + 50 - based on JS processing

            raw_responses = []
            self.log("Starting SSA download by reading required chunks...")

            for i, (cmd, size) in enumerate(zip(ssa_commands, ssa_sizes)):
                # Check for cancellation before each chunk
                if self.cancel_requested:
                    self.log(f"SSA download cancelled before reading chunk {i+1}")
                    return # Exit if cancelled

                try:
                    self.log(f"Reading SSA chunk {i+1}/{len(ssa_commands)} (Command: {hex_dump(cmd)}, Expecting: {size} bytes)")
                    
                    # Send the command
                    if not os_send_command(port_fd, cmd, f"SSA chunk {i+1} command"):
                        raise ValueError(f"Failed to send command for SSA chunk {i+1}")
                    
                    # Read the response with a longer timeout
                    # Use lambda for cancel check function
                    response = os_read_response(port_fd, size, 15, f"SSA chunk {i+1} data", 
                                              lambda: self.cancel_requested)
                    
                    # Check if cancelled during read
                    if self.cancel_requested:
                       self.log(f"SSA download cancelled while reading chunk {i+1}")
                       return # Exit if cancelled

                    # Check if we got enough data - needs exact size for this method
                    if len(response) != size:
                        self.log(f"Error: Received incomplete data ({len(response)}/{size} bytes) for SSA chunk {i+1}")
                        raise TimeoutError(f"Incomplete data received for SSA chunk {i+1}")
                        
                    self.log(f"Received {len(response)}/{size} bytes for SSA chunk {i+1}")
                    raw_responses.append(response)
                    
                    # Update progress (relative to number of SSA chunks)
                    progress = ((i + 1) / len(ssa_commands)) * 100
                    self.update_progress(progress)
                    
                    # Small delay between chunks maybe?
                    time.sleep(0.1)
                    
                except Exception as e:
                    self.log(f"Error reading SSA chunk {i+1}: {e}")
                    # If any chunk fails, we can't reconstruct the SSA data
                    raise # Re-raise the exception to be caught by the outer block

            # --- Process the received chunks --- 
            self.log("All SSA chunks received. Processing...")
            if len(raw_responses) != len(ssa_commands):
                self.log(f"Error: Did not receive all expected SSA chunks ({len(raw_responses)}/{len(ssa_commands)})")
                return
                
            # Combine buffers, skipping 2-byte header on each (as per JS logic)
            # Final expected size is 166*4 + 50 = 714
            final_ssa_data = bytearray(expected_final_data_size)
            current_offset = 0
            bytes_to_copy = [166, 166, 166, 166, 50] # Expected data size per chunk AFTER header removal
            
            for i, response_buffer in enumerate(raw_responses):
                header_size = 2
                # Ensure we don't try to read past the end of the buffer or copy wrong amount
                if len(response_buffer) >= header_size + bytes_to_copy[i]:
                    data_chunk = response_buffer[header_size : header_size + bytes_to_copy[i]]
                    final_ssa_data[current_offset : current_offset + len(data_chunk)] = data_chunk
                    current_offset += len(data_chunk)
                else:
                    self.log(f"Error: SSA Chunk {i+1} response too short ({len(response_buffer)} bytes) to extract expected data ({bytes_to_copy[i]} bytes after header)")
                    # Decide how to handle this - maybe save partial anyway?
                    # For now, let's stop processing
                    raise ValueError(f"SSA Chunk {i+1} response too short")
            
            # Trim if needed (shouldn't be if logic is right)
            if current_offset != expected_final_data_size:
                 self.log(f"Warning: Final SSA data size mismatch. Expected {expected_final_data_size}, got {current_offset}. Trimming.")
                 final_ssa_data = final_ssa_data[:current_offset]

            # Save the result
            if len(final_ssa_data) > 0:
                # Save the reconstructed SSA data
                ssa_filename = "SSA_downloaded.bin" # Use different name
                with open(ssa_filename, "wb") as outfile:
                    outfile.write(final_ssa_data)
                self.log(f"Successfully reconstructed SSA data. Saved {len(final_ssa_data)} bytes to {ssa_filename}")
                
                # Also save raw chunk data for analysis
                raw_filename = "SSA_downloaded.raw_chunks.bin"
                with open(raw_filename, "wb") as rawfile:
                    for i, buffer in enumerate(raw_responses):
                        rawfile.write(buffer)
                self.log(f"Saved raw chunk responses to {raw_filename} for analysis")
                
                # Compare with reference SSA.bin if exists
                try:
                    with open("SSA.bin", "rb") as ref_file:
                        ref_data = ref_file.read()
                        self.log(f"Reference SSA.bin size: {len(ref_data)} bytes")
                        
                        # Compare with our data
                        if len(final_ssa_data) != len(ref_data):
                             self.log(f"Warning: Downloaded SSA size ({len(final_ssa_data)}) differs from reference SSA.bin size ({len(ref_data)})")
                        
                        min_size = min(len(final_ssa_data), len(ref_data))
                        if min_size > 0:
                            match_bytes = 0
                            diff_offsets = []
                            max_diffs_to_show = 20
                            for i in range(min_size):
                                if final_ssa_data[i] == ref_data[i]:
                                    match_bytes += 1
                                elif len(diff_offsets) < max_diffs_to_show:
                                    # Store offset and the differing bytes
                                    diff_offsets.append((i, final_ssa_data[i], ref_data[i]))
                                    
                            match_percent = (match_bytes / min_size) * 100
                            self.log(f"SSA data match vs SSA.bin: {match_percent:.1f}% ({match_bytes}/{min_size} bytes)")
                            
                            # Print details of the first few differences
                            if diff_offsets:
                                self.log(f"First {len(diff_offsets)} byte differences (Offset: Downloaded != Reference):")
                                for offset, downloaded_byte, ref_byte in diff_offsets:
                                     self.log(f"  0x{offset:04X}: 0x{downloaded_byte:02X} != 0x{ref_byte:02X}")
                        else:
                             self.log("Cannot compare empty data.")
                             
                except FileNotFoundError:
                    self.log("Reference SSA.bin not found - cannot compare")
                except Exception as e:
                    self.log(f"Error comparing with reference SSA.bin: {e}")
                    
                # --- Automatically Trigger Analysis ---
                self.analyze_data(final_ssa_data)
                    
            else:
                self.log("Failed to reconstruct SSA data from chunks.")

        except Exception as e:
            self.log(f"SSA download failed: {e}")
            import traceback
            self.log(traceback.format_exc())
        finally:
            # Don't clean up ports - keep the OS handle active for potential restart
            # Just reset busy state
            self.root.after(0, self.set_busy, False)

    def cancel_operation(self):
        """Request to cancel the current operation."""
        if self.is_busy:
            self.log("Cancellation requested. Waiting for operations to complete...")
            self.cancel_requested = True
            # Update UI to indicate cancellation is pending
            self.cancel_button.configure(text="Cancelling...", state=tk.DISABLED)

    def on_closing(self):
        """Handle window closing cleanly."""
        if self.is_busy:
            result = messagebox.askquestion("Busy", 
                       "An operation is in progress. Cancel and force close the window?", 
                       icon='warning')
            if result == 'yes':
                self.log("Force closing application...")
                # Force cleanup, set force_exit flag, and close
                self.cancel_requested = True
                self.force_exit = True
                self.cleanup_ports()
                self.root.destroy()
            return # Don't close yet unless user confirmed

        self.cleanup_ports()
        self.root.destroy()

    # --- VIN Analysis Functions (Adapted from vin_viewer.py) ---
    VIN_REGEX = {
        "all": re.compile(b'[A-HJ-NPR-Z0-9]{17}'),
        "saab": re.compile(b'YS3[A-HJ-NPR-Z0-9]{14}')
        # Add other specific prefixes if needed (WVW, WBA, 1G, SCC, JTH, WP0, WAU)
    }

    KNOWN_OFFSETS = [
        # Example offsets from vin_viewer - adjust if needed for Tech2
        0x5CBE80, 
        0x820800, 
        0xFE0000, # This is where our SSA data starts conceptually
        0x14 # Calculated start offset of VIN within downloaded SSA data (0x16 in raw - 2 header)
    ]

    def find_vins(self, data, scan_type="all", use_known_offsets=True, context_size=32):
        """Find VINs in the provided binary data"""
        self.log("Starting VIN analysis...")
        found_vins = []
        regex = self.VIN_REGEX.get(scan_type, self.VIN_REGEX["all"]) # Default to all

        # 1. Check known offsets
        if use_known_offsets:
            self.log("Checking known offsets...")
            for offset in self.KNOWN_OFFSETS:
                if offset + 17 <= len(data):
                    chunk = data[offset:offset+17]
                    if regex.fullmatch(chunk):
                        vin_str = chunk.decode('ascii')
                        self.log(f"VIN found at known offset 0x{offset:X}: {vin_str}")
                        hex_dump_str = self.print_hex_dump(data, offset, context_size)
                        found_vins.append({
                            'vin': vin_str,
                            'offset': offset,
                            'context': hex_dump_str,
                            'method': 'known_offset'
                        })
                        # Optionally break after first find at known offset?

        # 2. Scan entire data
        self.log("Scanning entire data...")
        for match in regex.finditer(data):
            offset = match.start()
            vin_bytes = match.group(0)
            vin_str = vin_bytes.decode('ascii')
            
            # Avoid duplicates if found by known offset scan already
            if any(v['vin'] == vin_str and v['offset'] == offset for v in found_vins):
                continue

            self.log(f"VIN found via full scan at offset 0x{offset:X}: {vin_str}")
            hex_dump_str = self.print_hex_dump(data, offset, context_size)
            found_vins.append({
                'vin': vin_str,
                'offset': offset,
                'context': hex_dump_str,
                'method': 'full_scan'
            })

        self.log(f"VIN analysis complete. Found {len(found_vins)} potential VIN(s).")
        return found_vins

    def print_hex_dump(self, data, highlight_offset, context_size=32):
        """Generate a hex dump string centered around the highlight_offset"""
        start = max(0, highlight_offset - context_size // 2)
        end = min(len(data), highlight_offset + 17 + context_size // 2) # Show VIN + context
        
        dump_lines = []
        bytes_per_line = 16
        
        for i in range(start, end, bytes_per_line):
            chunk = data[i:min(i + bytes_per_line, end)]
            hex_str = ' '.join(f'{b:02X}' for b in chunk)
            ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            line = f"  0x{i:08X}  {hex_str:<{bytes_per_line*3}}  |{ascii_str:<{bytes_per_line}}|"
            dump_lines.append(line)
            
        return "\n".join(dump_lines)

    # --- New Methods for Analysis --- 
    def create_analysis_context_menu(self):
        """Create right-click menu for the analysis text area."""
        self.analysis_context_menu = tk.Menu(self.analysis_area, tearoff=0)
        self.analysis_context_menu.add_command(label="Copy", command=self.copy_analysis_selection)
        self.analysis_context_menu.add_command(label="Select All", command=self.select_all_analysis)
        self.analysis_area.bind("<Button-3>", self.show_analysis_context_menu)

    def show_analysis_context_menu(self, event):
        self.analysis_context_menu.post(event.x_root, event.y_root)

    def copy_analysis_selection(self):
        try:
            selected_text = self.analysis_area.get(tk.SEL_FIRST, tk.SEL_LAST)
            pyperclip.copy(selected_text)
        except tk.TclError: # No selection
            pass 
        except Exception as e:
            self.log(f"Error copying analysis text: {e}")

    def select_all_analysis(self):
        self.analysis_area.tag_add(tk.SEL, "1.0", tk.END)
        
    def analyze_ssa_file(self):
        """Manually trigger analysis of the saved SSA file."""
        file_path = "SSA_downloaded.bin"
        if not os.path.exists(file_path):
            messagebox.showerror("File Not Found", f"{file_path} not found. Please download SSA data first.")
            return
            
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            self.analyze_data(data)
        except Exception as e:
            messagebox.showerror("Analysis Error", f"Failed to read or analyze {file_path}: {e}")
            self.log(f"Error during manual analysis: {e}")
            
    def analyze_data(self, data):
        """Performs VIN analysis on the provided data and updates the UI."""
        if not data:
            self.log("No data provided for analysis.")
            return
            
        self.clear_analysis_area() # Clear previous results
        self.log("Starting analysis of downloaded SSA data...")
        
        # Call the find_vins function (already part of the class)
        # Using default settings: all VINs, known offsets, context 32
        results = self.find_vins(data, scan_type="all", use_known_offsets=True, context_size=32)
        
        # Display results in the analysis area
        if not results:
            self.display_analysis_result("No VINs found in the provided data.")
        else:
            self.display_analysis_result(f"Found {len(results)} potential VIN(s):\n")
            for i, vin_info in enumerate(results):
                # --- Extract Separator and Security Codes ---
                vin_offset = vin_info['offset']
                vin_end_offset = vin_offset + 17
                separator_offset = vin_end_offset
                sec_code_start_offset = separator_offset + 1
                sec_code_end_offset = sec_code_start_offset + 8 # 4+4 bytes

                separator_byte = None
                separator_hex = "N/A"
                immo_code = "N/A"
                info_code = "N/A"

                # Get separator byte
                if separator_offset < len(data):
                    separator_byte = data[separator_offset:separator_offset+1]
                    separator_hex = hex_dump(separator_byte)

                # Get security codes if there's enough data
                if sec_code_end_offset <= len(data):
                    immo_bytes = data[sec_code_start_offset : sec_code_start_offset + 4]
                    info_bytes = data[sec_code_start_offset + 4 : sec_code_end_offset]
                    try:
                        # Attempt to decode as ASCII, replace errors
                        immo_code = immo_bytes.decode('ascii', errors='replace')
                        info_code = info_bytes.decode('ascii', errors='replace')
                        # If decoding resulted in non-printable chars, fallback to hex
                        if not all(32 <= ord(c) <= 126 for c in immo_code):
                             immo_code = f"(Hex: {hex_dump(immo_bytes)})"
                        if not all(32 <= ord(c) <= 126 for c in info_code):
                             info_code = f"(Hex: {hex_dump(info_bytes)})"
                             
                    except Exception:
                        # Fallback to hex if decoding fails badly
                        immo_code = f"(Hex: {hex_dump(immo_bytes)})"
                        info_code = f"(Hex: {hex_dump(info_bytes)})"
                # --- End Extraction --- 
                
                result_str = (
                    f"VIN #{i+1}: {vin_info['vin']}\n" 
                    f"  Method: {vin_info['method']}\n"
                    f"  Offset: 0x{vin_info['offset']:08X}\n"
                    f"  Separator (at 0x{separator_offset:08X}): {separator_hex}\n"
                    f"  Immo Sec Code (4 bytes): {immo_code}\n"
                    f"  Info Sec Code (4 bytes): {info_code}\n"
                    f"  Context:\n{vin_info['context']}\n"
                    f"--------------------\n"
                )
                self.display_analysis_result(result_str)
                
        self.log("Analysis results displayed.")
        
    def display_analysis_result(self, text):
         """Append text to the analysis results text area."""
         try:
             if self.analysis_area.winfo_exists():
                 self.analysis_area.configure(state='normal')
                 self.analysis_area.insert(tk.END, text)
                 self.analysis_area.configure(state='disabled')
                 self.analysis_area.see(tk.END)
         except Exception as e:
             self.log(f"Error displaying analysis result: {e}")
             
    def clear_analysis_area(self):
        """Clear the analysis results text area."""
        try:
            if self.analysis_area.winfo_exists():
                self.analysis_area.configure(state='normal')
                self.analysis_area.delete(1.0, tk.END)
                self.analysis_area.configure(state='disabled')
        except Exception as e:
            self.log(f"Error clearing analysis area: {e}")
    # --- End New Methods ---

# --- Main Execution ---
if __name__ == "__main__":
    # Global log function
    log = print
    
    # Make the app more responsive to DPI settings if possible
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass # Ignore if not on Windows or unsupported

    root = tk.Tk()
    app = Tech2ReaderApp(root)
    root.mainloop() 