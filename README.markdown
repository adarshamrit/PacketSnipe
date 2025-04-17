# Network Packet Analyzer 🌐🔍

## Overview 🚀

The **Network Packet Analyzer** is a Python-based GUI application built with `tkinter`, `scapy`, and `matplotlib` 🎨. It’s your go-to tool for capturing, analyzing, and visualizing network packets in real-time with a fun and user-friendly interface 😄. Apply packet filters, view summaries, save data, and enjoy dynamic graphs showcasing traffic trends and protocol distributions 📊.

Perfect for network admins, security geeks, or anyone curious about network traffic! 🕵️‍♂️

---

## Features ✨

- **Packet Capture** 🕸️: Snag network packets with custom filters (e.g., `tcp`, `udp`, `port 80`).
- **Real-Time Display** 📜: Watch packet summaries scroll in a neat text area.
- **Dynamic Visualization** 📈:
  - Line graph tracking packet capture trends over time ⏱️.
  - Pie chart showing protocol distribution (TCP, UDP, ICMP) 🥧.
- **Save Captured Data** 💾: Export packet summaries to `captured_packets.txt`.
- **Clear Output** 🧹: Wipe the text area clean for a fresh start.
- **Responsive GUI** 🖥️: Font size adjusts dynamically when you resize the window.
- **Status Updates** 🔔: Stay in the loop with real-time status (e.g., "Capturing packets...", "Idle").

---

## Requirements 🛠️

To get this app running, you’ll need:

- **Python** 🐍: Version 3.6 or higher.
- **tkinter** 🖼️: Usually comes with Python; powers the GUI.
- **scapy** 📡: For capturing and analyzing packets.
- **matplotlib** 📊: For those slick real-time graphs.
- **numpy** 🔢: Optional, used by `matplotlib` for numerical magic.
- **Npcap** (Windows only) 🪟: Required for packet capturing on Windows.

### Installation Steps 📋

1. **Install Python** 🐍:

   - Grab Python from python.org and install it.

2. **Install Python Packages** 📦:

   ```bash
   pip install scapy matplotlib
   ```

3. **Install Npcap (Windows Only)** 🪟:

   - Npcap is required for `scapy` to capture packets on Windows.
   - **Steps**:
     1. Download Npcap from npcap.com.
     2. Run the installer and follow the prompts.
     3. Ensure the "Install Npcap in WinPcap API-compatible mode" option is checked.
     4. Restart your computer if prompted.
   - **Note**: You may need administrative privileges to install Npcap.

4. **Run with Admin Privileges** 🔐:

   - `scapy` needs administrative/root privileges to capture packets.
   - On Windows, right-click your terminal (e.g., Command Prompt or PowerShell) and select "Run as administrator".
   - On Linux, use `sudo` (e.g., `sudo python packet_sniffer.py`).

---

## Usage 🎮

1. **Run the Application** 🏃‍♂️:

   ```bash
   python packet_sniffer.py
   ```

   Replace `packet_sniffer.py` with your script’s name.

2. **GUI Layout** 🖱️:

   - **Filter Entry** ✍️: Type a filter (e.g., `tcp`, `udp`, `port 80`) to capture specific packets.
   - **Buttons** 🛎️:
     - **Start Capture** ▶️: Kick off packet capturing with your filter.
     - **Stop Capture** ⏹️: Pause the capture process.
     - **Save to File** 💾: Save packet summaries to `captured_packets.txt`.
     - **Show Graphs** 📉: Pop up real-time graphs for trends and protocols.
     - **Clear Output** 🗑️: Clear the packet summary display.
   - **Text Area** 📄: Shows live packet summaries.
   - **Packet Count** 🔢: Tracks total captured packets.
   - **Status Bar** ℹ️: Displays current state (e.g., "Idle", "Capturing packets...").

3. **Capturing Packets** 🕵️:

   - Enter a filter (optional) and hit **Start Capture** ▶️.
   - Watch packet summaries roll in the text area.
   - Click **Stop Capture** ⏹️ to halt.

4. **Visualizing Data** 📊:

   - Click **Show Graphs** 📉 to see:
     - A line graph of packets captured over time 📈.
     - A pie chart of protocol distribution (TCP, UDP, ICMP) 🥧.
   - Graphs refresh every second for real-time vibes ⏰.

5. **Saving Data** 💾:

   - After stopping, click **Save to File** to dump summaries to `captured_packets.txt`.

---

## Code Structure 🏗️

The app is packed into a single Python script with these key pieces:

### Main Components 🧩

- **PacketSnifferApp Class** 🖥️:

  - Runs the show for GUI and packet capturing.
  - **Attributes**:
    - `master`: The `tkinter` root window.
    - `running`: Boolean to toggle packet capturing.
    - `packet_count`: Counts captured packets.
    - `captured_packets`: Stores captured packets.
    - `protocol_counter`: Tracks protocol distribution (TCP, UDP, ICMP).
    - `time_data`: Logs packet counts for trends.
  - **Methods**:
    - `__init__`: Sets up the GUI and scaling.
    - `update_layout`: Tweaks font size based on window size.
    - `start_sniffing`: Fires up packet capture in a thread.
    - `stop_sniffing`: Stops capturing.
    - `sniff_packets`: Grabs packets with `scapy`.
    - `display_packet`: Processes and shows packet info.
    - `save_to_file`: Saves summaries to a file.
    - `clear_output`: Clears the text area.
    - `show_graphs`: Spins up real-time graphs.

- **main Function** 🚪:

  - Boots up the `tkinter` window and starts the app.

### Key Dependencies 📚

- `tkinter` 🖼️: Builds the GUI (buttons, text area, etc.).
- `scapy` 📡: Captures and filters packets.
- `threading` 🧵: Runs capturing in a separate thread to keep the GUI smooth.
- `matplotlib` 📊: Powers line graphs and pie charts.
- `collections.Counter` 🔢: Counts protocol occurrences.

---

## Implementation Details 🔍

### GUI Design 🎨

- Built with `tkinter` for a clean, responsive layout.
- Widgets are packed or gridded for tidy placement.
- Text area font scales with window size for readability 📏.
- Buttons are grouped in a frame for a polished look.

### Packet Capturing 📡

- Uses `scapy`’s `sniff` function to grab packets.
- Runs in a separate `Thread` to keep the GUI responsive.
- Filters (e.g., `tcp`, `port 80`) are passed to `sniff`.
- `display_packet` updates the GUI and tracks protocols.

### Visualization 📈

- **Packet Traffic Graph** 📉:
  - Line graph plots packet counts over time.
  - Refreshes every second via `FuncAnimation`.
- **Protocol Distribution** 🥧:
  - Pie chart shows TCP, UDP, ICMP percentages.
  - Uses red, green, blue for visual pop 🌈.
  - Updates every second with `FuncAnimation`.

### Data Storage 💾

- Packets are stored in `captured_packets` (list).
- `save_to_file` writes summaries to `captured_packets.txt`.

---

## Limitations ⚠️

- **Privileges** 🔐: Needs admin/root access for `scapy`.
- **Platform** 🖥️: Tested on Windows/Linux; macOS may need tweaks.
- **Filters** ✍️: Invalid filter strings can cause errors—stick to `scapy` syntax.
- **Performance** 🐢: High packet volumes may slow the GUI or eat memory.
- **Visualization** 📊: Graphs may lag with tons of packets.

---

## Future Improvements 🌟

- **Advanced Filters** 🔎: Add a dropdown for common filters or validate syntax.
- **Packet Details** 📋: Show source/destination IP, payload, etc.
- **Export Formats** 📄: Support PCAP, CSV, or JSON exports.
- **Performance Boost** ⚡: Buffer packets or limit displayed data.
- **Cross-Platform Love** 🌍: Ensure macOS compatibility.
- **Error Handling** 🛡️: Better messages for bad filters or missing privileges.

---

## Troubleshooting 🩺

- **"Permission Denied" Error** 🚫:
  - Run with admin privileges (e.g., `sudo` on Linux or "Run as administrator" on Windows).
- **No Packets Captured** 😕:
  - Check if the network interface is active and traffic exists.
  - Verify filter syntax (e.g., `tcp` not `TCP`).
- **GUI Freezes** 🥶:
  - Stop capturing or reduce packet rate.
- **Graphs Not Updating** 📉:
  - Ensure `matplotlib` is installed and no errors during graph setup.
- **Npcap Issues** 🪟:
  - Reinstall Npcap or ensure WinPcap compatibility mode is enabled.

---

## License 📜

This project is licensed under the **GNU General Public License v3.0** 🗽. You’re free to use, modify, and share it, as long as you keep it open-source and share your changes under the same license. See LICENSE for details.

---

## Contact 📧

Got questions or ideas? Reach out to the project maintainer or open an issue on the repo (if available). Let’s make this tool even cooler! 😎