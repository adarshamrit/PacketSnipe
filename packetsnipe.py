import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import sniff
from threading import Thread
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
from collections import Counter, defaultdict
import time


class PacketSnifferApp:
    def __init__(self, master):
        self.master = master
        self.master.title("PacketSnipe V0.1a")
        self.running = False
        self.packet_count = 0
        self.captured_packets = []
        self.protocol_counter = Counter()
        self.time_data = []
        self.packet_sizes = []
        self.top_talkers = defaultdict(int)
        self.capture_limit = tk.IntVar(value=0)
        self.capture_duration = tk.IntVar(value=0)
        self.start_time = None
        self.dark_mode = tk.BooleanVar()

        self.master.geometry("900x600")
        self.master.minsize(700, 400)
        self.master.bind("<Configure>", self.update_layout)

        self.style = ttk.Style()
        self.toggle_theme()

        self.filter_label = tk.Label(master, text="Filter:")
        self.filter_label.pack(pady=5)

        filter_frame = tk.Frame(master)
        filter_frame.pack(fill=tk.X, padx=10)

        self.filter_entry = tk.Entry(filter_frame)
        self.filter_entry.pack(side=tk.LEFT, expand=True, fill=tk.X)

        self.filter_dropdown = ttk.Combobox(filter_frame, values=["", "tcp", "udp", "icmp", "port 80"])
        self.filter_dropdown.pack(side=tk.LEFT, padx=5)
        self.filter_dropdown.bind("<<ComboboxSelected>>", lambda e: self.filter_entry.delete(0, tk.END) or self.filter_entry.insert(0, self.filter_dropdown.get()))

        options_frame = tk.Frame(master)
        options_frame.pack(pady=5)

        tk.Label(options_frame, text="Limit (packets):").grid(row=0, column=0)
        tk.Entry(options_frame, textvariable=self.capture_limit, width=6).grid(row=0, column=1, padx=5)
        tk.Label(options_frame, text="Duration (seconds):").grid(row=0, column=2)
        tk.Entry(options_frame, textvariable=self.capture_duration, width=6).grid(row=0, column=3, padx=5)
        tk.Checkbutton(options_frame, text="Dark Mode", variable=self.dark_mode, command=self.toggle_theme).grid(row=0, column=4, padx=10)

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

        self.tree = ttk.Treeview(master, columns=("Time", "Source", "Destination", "Protocol"), show="headings")
        for col in self.tree["columns"]:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.tree.bind("<Double-1>", self.show_packet_details)

        self.packet_count_label = tk.Label(master, text="Packets Captured: 0")
        self.packet_count_label.pack(pady=5)

        self.status_label = tk.Label(master, text="Status: Idle", bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_label.pack(fill=tk.X, side=tk.BOTTOM)

    def update_layout(self, event):
        pass

    def toggle_theme(self):
        if self.dark_mode.get():
            self.master.configure(bg="#2e2e2e")
            self.style.theme_use("clam")
            self.style.configure("Treeview", background="#2e2e2e", foreground="white", fieldbackground="#2e2e2e")
        else:
            self.master.configure(bg="SystemButtonFace")
            self.style.theme_use("default")
            self.style.configure("Treeview", background="white", foreground="black", fieldbackground="white")

    def start_sniffing(self):
        self.running = True
        self.packet_count = 0
        self.captured_packets.clear()
        self.protocol_counter.clear()
        self.time_data.clear()
        self.packet_sizes.clear()
        self.top_talkers.clear()
        self.tree.delete(*self.tree.get_children())
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.save_button.config(state=tk.DISABLED)
        self.status_label.config(text="Status: Capturing packets...")
        self.start_time = time.time()
        Thread(target=self.sniff_packets, daemon=True).start()

    def stop_sniffing(self):
        self.running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.save_button.config(state=tk.NORMAL)
        self.status_label.config(text="Status: Idle")

    def sniff_packets(self):
        filter_text = self.filter_entry.get()
        try:
            sniff(filter=filter_text, prn=self.display_packet,
                  stop_filter=lambda _: not self.running or self.capture_limit_reached() or self.capture_duration_reached())
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def capture_limit_reached(self):
        return self.capture_limit.get() > 0 and self.packet_count >= self.capture_limit.get()

    def capture_duration_reached(self):
        return self.capture_duration.get() > 0 and (time.time() - self.start_time) >= self.capture_duration.get()

    def display_packet(self, packet):
        self.packet_count += 1
        self.packet_count_label.config(text=f"Packets Captured: {self.packet_count}")
        self.captured_packets.append(packet)
        self.time_data.append(self.packet_count)
        self.packet_sizes.append(len(packet))

        src = packet[0].src if hasattr(packet[0], 'src') else 'N/A'
        dst = packet[0].dst if hasattr(packet[0], 'dst') else 'N/A'
        proto = packet.sprintf("%IP.proto%") if packet.haslayer("IP") else packet.name
        timestamp = time.strftime("%H:%M:%S", time.localtime())
        self.tree.insert("", tk.END, values=(timestamp, src, dst, proto))

        self.top_talkers[src] += 1
        if packet.haslayer("TCP"):
            self.protocol_counter["TCP"] += 1
        elif packet.haslayer("UDP"):
            self.protocol_counter["UDP"] += 1
        elif packet.haslayer("ICMP"):
            self.protocol_counter["ICMP"] += 1

    def save_to_file(self):
        if self.captured_packets:
            with open("captured_packets.txt", "w") as f:
                for packet in self.captured_packets:
                    f.write(packet.summary() + "\n")
            messagebox.showinfo("Saved", "Packets saved to 'captured_packets.txt'.")
        else:
            messagebox.showwarning("No Data", "No packets to save.")

    def clear_output(self):
        self.tree.delete(*self.tree.get_children())
        self.packet_count = 0
        self.packet_count_label.config(text="Packets Captured: 0")

    def show_packet_details(self, event):
        selected = self.tree.focus()
        index = self.tree.index(selected)
        if selected and index < len(self.captured_packets):
            packet = self.captured_packets[index]
            detail_window = tk.Toplevel(self.master)
            detail_window.title("Packet Details")
            text = tk.Text(detail_window, wrap=tk.WORD)
            text.pack(expand=True, fill=tk.BOTH)
            text.insert(tk.END, packet.show(dump=True))

    def show_graphs(self):
        fig, ax = plt.subplots(3, 1, figsize=(8, 8))

        def update_traffic(frame):
            ax[0].clear()
            ax[0].plot(range(len(self.time_data)), self.time_data, color='blue')
            ax[0].set_title("Packet Capture Over Time")
            ax[0].set_ylabel("Total Packets")

        def update_bandwidth(frame):
            ax[1].clear()
            if self.packet_sizes:
                ax[1].plot(range(len(self.packet_sizes)), self.packet_sizes, color='purple')
                ax[1].set_title("Bandwidth Usage (Bytes per Packet)")
                ax[1].set_ylabel("Bytes")

        def update_protocol(frame):
            ax[2].clear()
            labels, sizes = zip(*self.protocol_counter.items()) if self.protocol_counter else ([], [])
            ax[2].pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
            ax[2].set_title("Protocol Distribution")

        ani1 = FuncAnimation(fig, update_traffic, interval=1000)
        ani2 = FuncAnimation(fig, update_bandwidth, interval=1000)
        ani3 = FuncAnimation(fig, update_protocol, interval=1000)

        plt.tight_layout()
        plt.figure()
        if self.top_talkers:
            labels, values = zip(*sorted(self.top_talkers.items(), key=lambda item: item[1], reverse=True))
            plt.bar(labels[:10], values[:10], color='orange')
            plt.title("Top Talkers (Source IP)")
            plt.ylabel("Packet Count")
            plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        plt.show()


def main():
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()