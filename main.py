import tkinter as tk
from scapy.all import sniff
from threading import Thread
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
from collections import Counter


class PacketSnifferApp:
    """A GUI-based network packet analyzer with graphical data visualization."""

    def __init__(self, master):
        """Initialize the GUI elements and configure scaling."""
        self.master = master
        self.master.title("PacketSnipe V0.1a")
        self.running = False
        self.packet_count = 0
        self.captured_packets = []
        self.protocol_counter = Counter()
        self.time_data = []

        # Configure window scaling
        self.master.geometry("700x500")
        self.master.minsize(500, 350)
        self.master.bind("<Configure>", self.update_layout)

        # Filter Entry
        self.filter_label = tk.Label(master, text="Filter (e.g., 'tcp', 'udp', 'port 80'):")
        self.filter_label.pack(pady=5)
        self.filter_entry = tk.Entry(master)
        self.filter_entry.pack(fill=tk.X, padx=10, pady=5)

        # Buttons
        button_frame = tk.Frame(master)
        button_frame.pack(pady=5, fill=tk.X)

        self.start_button = tk.Button(button_frame, text="Start Capture", command=self.start_sniffing)
        self.start_button.grid(row=0, column=0, padx=5)

        self.stop_button = tk.Button(button_frame, text="Stop Capture", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=1, padx=5)

        self.save_button = tk.Button(button_frame, text="Save to File", command=self.save_to_file, state=tk.DISABLED)
        self.save_button.grid(row=0, column=2, padx=5)

        self.visualize_button = tk.Button(button_frame, text="Show Graphs", command=self.show_graphs)
        self.visualize_button.grid(row=0, column=3, padx=5)

        self.clear_button = tk.Button(button_frame, text="Clear Output", command=self.clear_output)
        self.clear_button.grid(row=0, column=4, padx=5)

        # Text area for output
        self.text_area = tk.Text(master)
        self.text_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Packet count
        self.packet_count_label = tk.Label(master, text="Packets Captured: 0")
        self.packet_count_label.pack(pady=5)

        # Status bar
        self.status_label = tk.Label(master, text="Status: Idle", bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_label.pack(fill=tk.X, side=tk.BOTTOM)

    def update_layout(self, event):
        """Adjust font size dynamically based on window width."""
        new_size = int(event.width / 50)
        self.text_area.config(font=("Arial", new_size))

    def start_sniffing(self):
        """Start capturing packets."""
        self.running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.save_button.config(state=tk.DISABLED)
        self.status_label.config(text="Status: Capturing packets...")
        self.text_area.insert(tk.END, "Starting packet capture...\n")
        Thread(target=self.sniff_packets, daemon=True).start()

    def stop_sniffing(self):
        """Stop capturing packets."""
        self.running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.save_button.config(state=tk.NORMAL)
        self.status_label.config(text="Status: Idle")
        self.text_area.insert(tk.END, "Stopped packet capture.\n")

    def sniff_packets(self):
        """Capture packets and log traffic trends."""
        filter_text = self.filter_entry.get()
        try:
            sniff(filter=filter_text, prn=self.display_packet, stop_filter=lambda _: not self.running)
        except Exception as e:
            self.text_area.insert(tk.END, f"Error: {str(e)}\n")

    def display_packet(self, packet):
        """Store packet information and update protocol distribution."""
        self.packet_count += 1
        self.packet_count_label.config(text=f"Packets Captured: {self.packet_count}")
        self.text_area.insert(tk.END, packet.summary() + "\n")
        self.text_area.see(tk.END)
        self.captured_packets.append(packet)

        # Track protocol distribution
        if packet.haslayer("TCP"):
            self.protocol_counter["TCP"] += 1
        elif packet.haslayer("UDP"):
            self.protocol_counter["UDP"] += 1
        elif packet.haslayer("ICMP"):
            self.protocol_counter["ICMP"] += 1

        # Update time trend
        self.time_data.append(self.packet_count)

    def save_to_file(self):
        """Save captured packets to a file."""
        if self.captured_packets:
            with open("captured_packets.txt", "w") as f:
                for packet in self.captured_packets:
                    f.write(packet.summary() + "\n")
            self.text_area.insert(tk.END, "Packets saved to 'captured_packets.txt'.\n")
        else:
            self.text_area.insert(tk.END, "No packets to save.\n")

    def clear_output(self):
        """Clear the text area."""
        self.text_area.delete(1.0, tk.END)

    def show_graphs(self):
        """Generate and display real-time graphs for packet traffic trends and protocol distribution."""
        fig, ax = plt.subplots(2, 1, figsize=(7, 5))

        # Packet Traffic Graph
        def update_traffic_graph(frame):
            ax[0].clear()
            ax[0].plot(range(len(self.time_data)), self.time_data, color='blue', linestyle='-', marker='o')
            ax[0].set_title("Packet Capture Over Time")
            ax[0].set_xlabel("Time (Captured Packets)")
            ax[0].set_ylabel("Total Packets")

        # Protocol Pie Chart
        def update_protocol_chart(frame):
            ax[1].clear()
            labels, sizes = zip(*self.protocol_counter.items()) if self.protocol_counter else ([], [])
            ax[1].pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140, colors=['red', 'green', 'blue'])
            ax[1].set_title("Protocol Distribution")

        # Animate both graphs
        ani1 = FuncAnimation(fig, update_traffic_graph, interval=1000)
        ani2 = FuncAnimation(fig, update_protocol_chart, interval=1000)

        plt.tight_layout()
        plt.show()


def main():
    """Initialize the application."""
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()