import tkinter as tk
from scapy.all import sniff
from threading import Thread


class PacketSnifferApp:
    """A GUI-based network packet analyzer using Scapy and Tkinter."""
    
    def __init__(self, master):
        """Initialize the GUI elements and configure automatic scaling."""
        self.master = master
        self.master.title("Network Packet Analyzer")
        self.running = False

        # Initialize variables
        self.packet_count = 0
        self.captured_packets = []

        # Make the window scalable
        self.master.geometry("700x500")  # Set initial window size
        self.master.minsize(500, 350)  # Set minimum window size
        self.master.bind("<Configure>", self.update_layout)  # Bind resize event to adjust UI

        # Packet filter entry field
        self.filter_label = tk.Label(master, text="Filter (e.g., 'tcp', 'udp', 'port 80'):")
        self.filter_label.pack(pady=5)
        self.filter_entry = tk.Entry(master)
        self.filter_entry.pack(fill=tk.X, padx=10, pady=5)

        # Frame for buttons
        button_frame = tk.Frame(master)
        button_frame.pack(pady=5, fill=tk.X)

        self.start_button = tk.Button(button_frame, text="Start Capture", command=self.start_sniffing)
        self.start_button.grid(row=0, column=0, padx=5)

        self.stop_button = tk.Button(button_frame, text="Stop Capture", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=1, padx=5)

        self.save_button = tk.Button(button_frame, text="Save to File", command=self.save_to_file, state=tk.DISABLED)
        self.save_button.grid(row=0, column=2, padx=5)

        self.clear_button = tk.Button(button_frame, text="Clear Output", command=self.clear_output)
        self.clear_button.grid(row=0, column=3, padx=5)

        # Text area to display captured packets
        self.text_area = tk.Text(master)
        self.text_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Packet count label
        self.packet_count_label = tk.Label(master, text="Packets Captured: 0")
        self.packet_count_label.pack(pady=5)

        # Status bar
        self.status_label = tk.Label(master, text="Status: Idle", bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_label.pack(fill=tk.X, side=tk.BOTTOM)

    def update_layout(self, event):
        """Adjust font size dynamically based on window width."""
        new_size = int(event.width / 50)  # Change font size relative to window size
        self.text_area.config(font=("Arial", new_size))  

    def start_sniffing(self):
        """Start capturing network packets."""
        self.running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.save_button.config(state=tk.DISABLED)
        self.status_label.config(text="Status: Capturing packets...")
        self.text_area.insert(tk.END, "Starting packet capture...\n")
        Thread(target=self.sniff_packets, daemon=True).start()  # Run sniffing in a separate thread

    def stop_sniffing(self):
        """Stop capturing packets."""
        self.running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.save_button.config(state=tk.NORMAL)
        self.status_label.config(text="Status: Idle")
        self.text_area.insert(tk.END, "Stopped packet capture.\n")

    def sniff_packets(self):
        """Capture packets based on user-defined filter."""
        filter_text = self.filter_entry.get()
        try:
            sniff(filter=filter_text, prn=self.display_packet, stop_filter=lambda _: not self.running)
        except Exception as e:
            self.text_area.insert(tk.END, f"Error: {str(e)}\n")

    def display_packet(self, packet):
        """Update UI with captured packet summary."""
        self.packet_count += 1
        self.packet_count_label.config(text=f"Packets Captured: {self.packet_count}")
        self.text_area.insert(tk.END, packet.summary() + "\n")
        self.text_area.see(tk.END)  # Auto-scroll to the latest packet
        self.captured_packets.append(packet)

    def clear_output(self):
        """Clear the text area."""
        self.text_area.delete(1.0, tk.END)

    def save_to_file(self):
        """Save captured packets to a file."""
        if self.captured_packets:
            with open("captured_packets.txt", "w") as f:
                for packet in self.captured_packets:
                    f.write(packet.summary() + "\n")
            self.text_area.insert(tk.END, "Packets saved to 'captured_packets.txt'.\n")
        else:
            self.text_area.insert(tk.END, "No packets to save.\n")


def main():
    """Initialize the application."""
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()