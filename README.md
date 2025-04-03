# Tech2 SSA Reader & Analyzer

A Python GUI application using Tkinter and the `sv_ttk` theme to communicate with a Tech2 device via RS232 serial connection.

## Features

*   Reads Security System Access (SSA) data using the known 5-chunk method.
*   Applies a dark theme using `sv_ttk`.
*   Automatically analyzes the downloaded SSA data to extract:
    *   Vehicle Identification Number (VIN) - (YS3 format primarily tested)
    *   Separator byte
    *   Immobilizer Security Code (4 bytes)
    *   Info Security Code (4 bytes)
*   Displays analysis results, including hex context.
*   Compares downloaded SSA data against a reference `SSA.bin` file.
*   Provides a button to restart the Tech2 device.
*   Logs communication and analysis steps to the UI and `tech2_reader.log` file.

## Requirements

*   Python 3.x
*   Required packages: `pyserial`, `sv_ttk`, `pyperclip`
*   A reference `SSA.bin` file (714 bytes) in the same directory for comparison.

## Installation

1.  Clone this repository or download the files.
2.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

1.  Ensure your Tech2 is connected via a compatible RS232 adapter.
2.  Make sure a valid `SSA.bin` reference file is present.
3.  Run the application:
    ```bash
    python tech2_reader.py
    ```
4.  Select the correct COM port from the dropdown and click "Refresh" if needed.
5.  Click "Enter Download Mode". Wait for confirmation in the log area.
6.  Click "Read SSA". The application will read the 5 data chunks.
7.  Upon successful download:
    *   `SSA_downloaded.bin` will be saved.
    *   `SSA_downloaded.raw_chunks.bin` will be saved.
    *   The data will be automatically analyzed.
    *   Results (VIN, codes, context) will appear in the "VIN Analysis Results" box.
    *   Comparison results against `SSA.bin` will appear in the log area.
8.  Use the "Restart Tech2" button as needed (it remains active).
9.  Use the "Analyze SSA File" button to re-analyze the `SSA_downloaded.bin` file without re-downloading.

## License

MIT License 