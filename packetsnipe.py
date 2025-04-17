import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import sniff
from threading import Thread
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
from collections import Counter
from datetime import datetime


class PacketSnifferApp:
    def __init__(self, master):
        self.master = master
        self.master.title("PacketSnipe V0.1a")
        self.running = False
        self.packet_count = 0
        self.captured_packets = []
        self.protocol_counter = Counter()
        self.time_data = []

        self.master.geometry("900x600")
        self.master.minsize(600, 400)
        self.master.bind("<Configure>", self.update_layout)

        self.filter_label = tk.Label(master, text="Filter:")
        self.filter_label.pack(pady=5)

        self.filter_frame = tk.Frame(master)
        self.filter_frame.pack(fill=tk.X, padx=10)

        self.filter_options = ["", "tcp", "udp", "icmp", "port 80"]
        self.filter_var = tk.StringVar()
        self.filter_dropdown = ttk.Combobox(self.filter_frame, textvariable=self.filter_var, values=self.filter_options)
        self.filter_dropdown.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.custom_filter_entry = tk.Entry(self.filter_frame)
        self.custom_filter_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

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

        columns = ("time", "src", "dst", "proto")
        self.packet_tree = ttk.Treeview(master, columns=columns, show="headings")
        for col in columns:
            self.packet_tree.heading(col, text=col.title())
            self.packet_tree.column(col, anchor="center")
        self.packet_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.packet_tree.bind("<Double-1>", self.show_packet_details)

        self.packet_count_label = tk.Label(master, text="Packets Captured: 0")
        self.packet_count_label.pack(pady=5)

        self.status_label = tk.Label(master, text="Status: Idle", bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_label.pack(fill=tk.X, side=tk.BOTTOM)

    def update_layout(self, event):
        pass  # Not required for Treeview font scaling

    def start_sniffing(self):
        self.running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.save_button.config(state=tk.DISABLED)
        self.status_label.config(text="Status: Capturing packets...")
        Thread(target=self.sniff_packets, daemon=True).start()

    def stop_sniffing(self):
        self.running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.save_button.config(state=tk.NORMAL)
        self.status_label.config(text="Status: Idle")

    def sniff_packets(self):
        filter_text = self.custom_filter_entry.get() or self.filter_var.get()
        try:
            sniff(filter=filter_text, prn=self.display_packet, stop_filter=lambda _: not self.running)
        except Exception as e:
            messagebox.showerror("Sniffing Error", str(e))

    def display_packet(self, packet):
        self.packet_count += 1
        self.packet_count_label.config(text=f"Packets Captured: {self.packet_count}")
        self.captured_packets.append(packet)

        proto = "OTHER"
        if packet.haslayer("TCP"):
            self.protocol_counter["TCP"] += 1
            proto = "TCP"
        elif packet.haslayer("UDP"):
            self.protocol_counter["UDP"] += 1
            proto = "UDP"
        elif packet.haslayer("ICMP"):
            self.protocol_counter["ICMP"] += 1
            proto = "ICMP"

        timestamp = datetime.now().strftime("%H:%M:%S")
        src = packet[0].src if hasattr(packet[0], "src") else "N/A"
        dst = packet[0].dst if hasattr(packet[0], "dst") else "N/A"
        self.packet_tree.insert("", tk.END, values=(timestamp, src, dst, proto))

        self.time_data.append(self.packet_count)

    def show_packet_details(self, event):
        item = self.packet_tree.selection()
        if item:
            index = self.packet_tree.index(item)
            packet = self.captured_packets[index]
            detail_window = tk.Toplevel(self.master)
            detail_window.title("Packet Details")
            detail_text = tk.Text(detail_window, wrap=tk.WORD)
            detail_text.pack(fill=tk.BOTH, expand=True)
            detail_text.insert(tk.END, packet.show(dump=True))
            detail_text.config(state=tk.DISABLED)

    def save_to_file(self):
        if self.captured_packets:
            with open("captured_packets.txt", "w") as f:
                for packet in self.captured_packets:
                    f.write(packet.summary() + "\n")
            messagebox.showinfo("Save", "Packets saved to 'captured_packets.txt'.")
        else:
            messagebox.showinfo("Save", "No packets to save.")

    def clear_output(self):
        for i in self.packet_tree.get_children():
            self.packet_tree.delete(i)
        self.packet_count = 0
        self.packet_count_label.config(text="Packets Captured: 0")
        self.captured_packets.clear()
        self.protocol_counter.clear()
        self.time_data.clear()

    def show_graphs(self):
        fig, ax = plt.subplots(2, 1, figsize=(7, 5))

        def update_traffic_graph(frame):
            ax[0].clear()
            ax[0].plot(range(len(self.time_data)), self.time_data, color='blue', linestyle='-', marker='o')
            ax[0].set_title("Packet Capture Over Time")
            ax[0].set_xlabel("Time (Captured Packets)")
            ax[0].set_ylabel("Total Packets")

        def update_protocol_chart(frame):
            ax[1].clear()
            labels, sizes = zip(*self.protocol_counter.items()) if self.protocol_counter else ([], [])
            ax[1].pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140, colors=['red', 'green', 'blue'])
            ax[1].set_title("Protocol Distribution")

        FuncAnimation(fig, update_traffic_graph, interval=1000)
        FuncAnimation(fig, update_protocol_chart, interval=1000)
        plt.tight_layout()
        plt.show()


def main():
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()