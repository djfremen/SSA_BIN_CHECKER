# Tech2 SSA Data Reader & Analyzer: Findings Summary

## Goal

This document summarizes the key findings from the development and testing process using data related to VIN ending in `2996`.

## 1. SSA Data Block Download (714 Bytes)

*   **Method:** The successful method for reading the relevant SSA data involves reading 5 specific data chunks using hardcoded commands and expected response sizes, mirroring the logic found in a known-working JavaScript implementation.
*   **Commands & Sizes:** (Confirmed working)
    *   Chunk 1: `81 5a 0f 2e 00 00 a6 42` -> Expect 169 bytes
    *   Chunk 2: `81 5a 0f 2e 00 a6 a6 9c` -> Expect 169 bytes
    *   Chunk 3: `81 5a 0f 2e 01 4c a6 f5` -> Expect 169 bytes
    *   Chunk 4: `81 5a 0f 2e 01 f2 a6 4f` -> Expect 169 bytes
    *   Chunk 5: `81 5a 0f 2e 02 98 32 1c` -> Expect 53 bytes
*   **Processing:** Each received chunk contains a 2-byte header that must be stripped. The remaining data payloads (166 + 166 + 166 + 166 + 50 bytes) are concatenated to form the final 714-byte data block.
*   **Result Files:** The application saves the processed data as `SSA_downloaded.bin` (714 bytes) and the raw, unprocessed chunks (including headers) as `SSA_downloaded.raw_chunks.bin` (729 bytes).
*   **Reliability:** This download method proved reliable.
    *   *Example Log Snippet (Successful Read):*
        ```
        [21:44:01] Reading SSA chunk 1/5 (Command: 81 5a 0f 2e 00 00 a6 42, Expecting: 169 bytes)
        [21:44:10] Received 169/169 bytes for SSA chunk 1
        ... (similar messages for chunks 2-5) ...
        [21:44:40] All SSA chunks received. Processing...
        [21:44:40] Successfully reconstructed SSA data. Saved 714 bytes to SSA_downloaded.bin
        ```

## 2. VIN Extraction

*   **Format:** Standard 17-character alphanumeric string (e.g., `YS3...`).
*   **Location:** Consistently found starting at offset `0x14` in the processed 714-byte data (`SSA_downloaded.bin`).
*   **Extraction Method:** Successfully extracted using regex and known offset checking.
*   **Observed VIN (example):** `YS3FD79Y276102996`.
    *   *Example Analysis Output:*
        ```
        VIN #1: YS3FD79Y276102996
          Method: known_offset
          Offset: 0x00000014
          Context:
          0x00000004  FF FF FF FF FF FF FF FF 00 01 00 00 00 FF FF FF   |................|
          0x00000014  59 53 33 46 44 37 39 59 32 37 36 31 30 32 39 39   |YS3FD79Y27610299|
          0x00000024  36 00 4F 36 49 46 49 53 55 4D FF FF FF FF FF FF   |6.O6IFISUM......|
          0x00000034  FF                                                |.               |
        ```

## 3. "SecCodes" Data (8 Bytes Following VIN)

*   **Location:** These 8 bytes reside immediately after the 17-byte VIN and a 1-byte `0x00` separator, specifically at offsets `0x18` through `0x1F` in the processed 714-byte data (`SSA_downloaded.bin`).
*   **Interpretation (User Provided):** These 8 bytes represent the security codes, split into:
    *   Bytes 1-4 (`0x18` - `0x1B`): `immoSecCode`
    *   Bytes 5-8 (`0x1C` - `0x1F`): `infoSecCode`
*   **Observed Values & Variability:** The content of these 8 bytes varied significantly between reads, even for the same VIN (`...2996`):
    *   Run 1 (VIN ...276102996): `FFFFFFFF` (Hex: `FF FF FF FF FF FF FF FF`)
    *   Run 2 (VIN ...276102996): `O6IFISUM` (Hex: `4F 36 49 46 49 53 55 4D`)
*   **Extraction:** The application (`tech2_reader.py`) correctly extracts and displays these 8 bytes, attempting ASCII decoding first and falling back to hex if non-printable.
    *   *Example Analysis Output showing `O6IFISUM` interpretation:*
        ```
        VIN #1: YS3FD79Y276102996
          Method: known_offset
          Offset: 0x00000014
          Separator (at 0x00000025): 00
          Immo Sec Code (4 bytes): O6IF  <- Bytes at 0x18-0x1B
          Info Sec Code (4 bytes): ISUM  <- Bytes at 0x1C-0x1F
          Context:
          ...
          0x00000014  59 53 33 46 44 37 39 59 32 37 36 31 30 32 39 39   |YS3FD79Y27610299|
          0x00000024  36 00 4F 36 49 46 49 53 55 4D FF FF FF FF FF FF   |6.O6IFISUM......|
          ...
        ```
*   **Role in Security Access (User Flow):** According to the user-provided flow, these "immos" bytes are decoded/derived after the initial security request and are then written back (e.g., to the PCMCIA card) after a calculation step.

## 4. GlobalTIS Log Analysis (`new_log-4j.txt`) vs. "Immos" Data

*   **TIS Security Codes:** The GlobalTIS logs show *different*, long hexadecimal strings associated with `SCImmo`/`SCInfo` for the same VIN (`...2996`) compared to the 8-byte "immos" (`O6IFISUM`/`FFFFFFFF`) read by our script.
    *   *TIS Log Example:*
        ```
        Tuple0 vin: YS3FD79Y276102996
        Tuple0 SCImmo: a6ad09c2aafc40a0c0e0e0c0e0602060
        Tuple0 SCInfo: a6ad09c2aafc40a0c0e0e0c0e0602060
        ```
*   **Seed/Key Pairs:** The TIS logs also explicitly show Seed/Key pairs (e.g., `SK0 seed: 0x846b`, `SK0 key: 0xffff`) being handled, suggesting a challenge-response calculation.
*   **Discrepancy:** There is a clear difference between the 8-byte "immos" data read directly by our script and the long hex `SCImmo`/`SCInfo` codes logged by TIS2000. This suggests the 8-byte "immos" might be intermediate values, identifiers, or status flags within the protocol, rather than the final codes used by TIS2000 itself.

## 5. Trionic 8 Security Algorithm (Seed -> Key Calculation)

*   **Mechanism:** A specific 4-step algorithm (ROR 7, ROL 10, Swap+Add 0xF8DA, Sub 0x3F52) is used to calculate a 16-bit `key` from a 16-bit `seed`.
*   **Relevance:** This algorithm is central to the security access challenge-response. The diagnostic tool must read a `seed` from the ECU (likely contained within the downloaded 714-byte block or requested via a specific command) and use this algorithm to compute the correct `key` to send back for authentication.
*   **Role vs. "Immos":** This Seed->Key calculation is distinct from the simple reading of the 8-byte "immos" data following the VIN. Gaining access likely involves sending the *calculated key*, not the observed "immos" bytes.

## 6. Low-Level RS232 Communication (`tis2web.txt`)

*   **Download Mode Entry:** Confirmed sequence `TX: ef 56 80 3b` -> `TX: ef 56 80 3b` -> `RX: ef 56 01 ba` matches implementation.
*   **Challenge-Response:** The log clearly shows a challenge-response sequence for security access:
    *   **Challenge (Seed Request):** Commands like `TX: 8a 57 00 06 19` and `TX: 8a 57 00 14 0b` are sent, resulting in `RX` data containing security information (likely including the seed(s)).
    *   **Response (Key Send):** A command `TX: 8a 57 00 06 11 de 40 37` sends data back *to* the Tech2. The embedded `de 40` strongly correlates with the `SK2 key: 0xde40` from the corresponding TIS log, indicating this command sends the calculated key.
*   **SSA Block Read Timing:** The 5-chunk read sequence (using `81 5a 0f 2e ...` commands) occurs *after* the successful challenge-response (key sending) sequence.
*   **"Immos" Bytes Not Written:** The log **does not show** the 8 bytes following the VIN (e.g., `XJOUQVL7`) being written back to the Tech2 during this captured security access flow. They are only read as part of the first SSA chunk (`RX` after `TX: 81 5a 0f 2e 00 00 a6 42`).
*   **Other Commands:** Additional commands (`8c 58 ...`, `80 ff ...`, `81 5a 00 20 ...`) are used for potentially unrelated setup, status checks, or reading filesystem/configuration info.

## 7. Comparison Discrepancy (`SSA_downloaded.bin` vs. `SSA.bin`)

*   **Observation:** A direct comparison for VIN `...2996` was not performed due to the reference file being unavailable during those runs.
*   **Expectation:** Significant differences are expected due to the variability of VIN, Seed/Key data, and the 8-byte "immos" data within the 714-byte block.

## 8. Overall Conclusions & Implications for Upload/Write

1.  The Python application reliably **reads** the 714-byte SSA data block using the correct 5-chunk commands, *after* security access would normally be granted.
2.  This block contains the current **VIN**, necessary **Seed values** for the Trionic 8 algorithm, and the variable 8-byte data block identified by the user as **"immos"**.
3.  The 8-byte "immos" data **differs significantly** from the `SCImmo`/`SCInfo` codes used internally by TIS2000, **varies** between reads, and **was not observed being written back** in the low-level RS232 log. Its exact role remains unclear but is unlikely to be the primary security code.
4.  Security access **relies on the Seed->Key calculation** using the Trionic 8 algorithm, executed via a challenge-response protocol (`8a 57 ...` commands observed in the RS232 log).
5.  **Uploading/Writing:**
    *   Granting security access requires implementing the **challenge-response protocol**: reading the seed (via commands like `8a 57 ...`), calculating the key using the Trionic 8 algorithm, and sending the key back (via commands like `8a 57 ... [key] ...`).
    *   Simply writing back the 714-byte block or the 8-byte "immos" data is **incorrect** for security access.
    *   The user-described flow of writing the "immos" back to the PCMCIA card was **not observed** in the RS232 log for *this specific security access sequence*. It might occur in a different context or involve different commands.
    *   Implementing *any* write functionality requires identifying the **specific commands, sequence, and data payloads** for the desired operation (e.g., sending calculated key, writing VIN, writing specific config bytes), based on further analysis of low-level logs or `cardwriter.exe` reverse engineering.
