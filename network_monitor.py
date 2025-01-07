import json
import threading
from scapy.all import sniff
import time
from collections import Counter
import matplotlib.pyplot as plt
import tkinter as tk
from tkinter import ttk, messagebox


packets_data = []
protocol_counter = Counter()
ip_counter = Counter()
timestamp_counter = Counter()
ip_pairs_counter = Counter()
is_running = [False]


def clear_json_file():
    try:
        with open('network_traffic.json', mode='w', encoding='utf-8') as file:
            json.dump([], file, indent=4, ensure_ascii=False)
        print("JSON dosyası başarıyla temizlendi.")
        messagebox.showinfo("Başarılı", "JSON dosyası başarıyla temizlendi.")
    except Exception as e:
        print(f"JSON dosyasını temizlerken bir hata oluştu: {e}")
        messagebox.showerror("Hata", f"JSON dosyasını temizlerken bir hata oluştu: {e}")


class NetworkMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Ağ Trafiği İzleme Aracı")


        self.tree = ttk.Treeview(root, columns=("Timestamp", "Source IP", "Destination IP", "Protocol", "Size"), show="headings")
        self.tree.heading("Timestamp", text="Zaman")
        self.tree.heading("Source IP", text="Kaynak IP")
        self.tree.heading("Destination IP", text="Hedef IP")
        self.tree.heading("Protocol", text="Protokol")
        self.tree.heading("Size", text="Boyut (bytes)")
        self.tree.pack(fill=tk.BOTH, expand=True)


        self.start_button = tk.Button(root, text="Başlat", command=self.start_monitoring)
        self.start_button.pack(side=tk.LEFT, padx=10, pady=10)

        self.stop_button = tk.Button(root, text="Durdur", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=10, pady=10)

        self.visualize_button = tk.Button(root, text="Görselleştir", command=self.visualize_data)
        self.visualize_button.pack(side=tk.LEFT, padx=10, pady=10)


        self.clear_button = tk.Button(root, text="JSON Temizle", command=clear_json_file)
        self.clear_button.pack(side=tk.LEFT, padx=10, pady=10)

    def start_monitoring(self):
        is_running[0] = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.monitor_thread = threading.Thread(target=self.monitor_traffic)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()

    def stop_monitoring(self):
        is_running[0] = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def monitor_traffic(self):
        sniff(prn=self.process_packet, stop_filter=lambda _: not is_running[0])

    def process_packet(self, packet):
        if packet.haslayer("IP"):
            source_ip = packet["IP"].src
            destination_ip = packet["IP"].dst
            protocol = packet["IP"].proto
            packet_size = len(packet)
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())


            packet_info = {
                "Timestamp": timestamp,
                "Source IP": source_ip,
                "Destination IP": destination_ip,
                "Protocol": protocol,
                "Packet Size (bytes)": packet_size,
            }
            packets_data.append(packet_info)
            protocol_counter[protocol] += 1
            ip_counter[source_ip] += 1
            ip_counter[destination_ip] += 1
            timestamp_counter[timestamp] += 1
            ip_pairs_counter[(source_ip, destination_ip)] += 1


            with open("network_traffic.json", mode="w", encoding="utf-8") as file:
                json.dump(packets_data, file, indent=4, ensure_ascii=False)


            self.tree.insert("", "end", values=(timestamp, source_ip, destination_ip, protocol, packet_size))

    def visualize_data(self):
        visualize_protocol_distribution()
        visualize_ip_distribution()
        visualize_packet_count_over_time()
        visualize_ip_pairs()


def visualize_protocol_distribution():
    protocols = list(protocol_counter.keys())
    counts = list(protocol_counter.values())

    plt.figure(figsize=(8, 8))
    plt.pie(counts, labels=protocols, autopct='%1.1f%%', startangle=90)
    plt.title("Protokol Dağılımı")
    plt.show()

def visualize_ip_distribution():
    ips = list(ip_counter.keys())
    counts = list(ip_counter.values())

    plt.figure(figsize=(8, 8))
    plt.barh(ips, counts)
    plt.xlabel("Paket Sayısı")
    plt.ylabel("IP Adresi")
    plt.title("IP Adresi Dağılımı")
    plt.show()

def visualize_packet_count_over_time():
    timestamps = list(timestamp_counter.keys())
    counts = list(timestamp_counter.values())

    plt.figure(figsize=(10, 6))
    plt.plot(timestamps, counts, marker='o')
    plt.xticks(rotation=45)
    plt.xlabel("Zaman")
    plt.ylabel("Paket Sayısı")
    plt.title("Zamanla Paket Sayısı Dağılımı")
    plt.tight_layout()
    plt.show()

def visualize_ip_pairs():
    ip_pairs = list(ip_pairs_counter.keys())
    counts = list(ip_pairs_counter.values())

    ip_pairs_labels = [f"{pair[0]} -> {pair[1]}" for pair in ip_pairs]

    plt.figure(figsize=(10, 6))
    plt.barh(ip_pairs_labels, counts)
    plt.xlabel("Paket Sayısı")
    plt.ylabel("IP Çiftleri")
    plt.title("IP Adresi Çiftlerinin İletişimi")
    plt.tight_layout()
    plt.show()


if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkMonitorApp(root)
    root.mainloop()









