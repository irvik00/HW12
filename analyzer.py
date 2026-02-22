import pyshark
import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter
import os

class StablePCAPAnalyzer:

    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.dns_queries = []
        self.ip_connections = []
        self.protocol_counter = Counter()

    def analyze(self):
        print(f"[*] Анализ файла: {self.pcap_file}")

        cap = pyshark.FileCapture(self.pcap_file, keep_packets=False)

        for packet in cap:
            try:
                self._process_packet(packet)
            except Exception:
                continue

        cap.close()
        print("[✓] Анализ завершён")

        self.save_results()
        self.create_visualization()
        self.print_summary()

    def _process_packet(self, packet):
        # Считаем протокол
        if hasattr(packet, "highest_layer"):
            self.protocol_counter[packet.highest_layer] += 1

        timestamp = packet.sniff_time if hasattr(packet, "sniff_time") else None

        # IPv4
        if hasattr(packet, "ip"):
            self.ip_connections.append({
                "timestamp": timestamp,
                "src_ip": packet.ip.src,
                "dst_ip": packet.ip.dst,
                "protocol": packet.transport_layer
            })

        # IPv6
        elif hasattr(packet, "ipv6"):
            self.ip_connections.append({
                "timestamp": timestamp,
                "src_ip": packet.ipv6.src,
                "dst_ip": packet.ipv6.dst,
                "protocol": packet.transport_layer
            })

        # DNS
        if hasattr(packet, "dns"):
            if hasattr(packet.dns, "qry_name"):
                self.dns_queries.append({
                    "timestamp": timestamp,
                    "query": packet.dns.qry_name,
                    "type": "QUERY"
                })
            elif hasattr(packet.dns, "resp_name"):
                self.dns_queries.append({
                    "timestamp": timestamp,
                    "query": packet.dns.resp_name,
                    "type": "RESPONSE"
                })

    def save_results(self):
        os.makedirs("results", exist_ok=True)

        if self.dns_queries:
            df_dns = pd.DataFrame(self.dns_queries)
            df_dns.to_csv("results/dns_queries.csv", index=False)
            print(f"[+] DNS записей: {len(self.dns_queries)}")

        if self.ip_connections:
            df_ip = pd.DataFrame(self.ip_connections)
            df_ip.to_csv("results/ip_connections.csv", index=False)
            print(f"[+] IP соединений: {len(self.ip_connections)}")

    def create_visualization(self):
        if not self.protocol_counter:
            return

        os.makedirs("results", exist_ok=True)

        top_protocols = dict(self.protocol_counter.most_common(10))

        plt.figure(figsize=(10, 5))
        plt.bar(top_protocols.keys(), top_protocols.values())
        plt.xticks(rotation=45)
        plt.title("Распределение протоколов")
        plt.tight_layout()
        plt.savefig("protocol_distribution.png")
        plt.close()

        print("[+] График распределения протоколов сохранён")

    def print_summary(self):
        print("\n===== СВОДКА =====")
        print(f"Всего IP соединений: {len(self.ip_connections)}")
        print(f"Всего DNS записей: {len(self.dns_queries)}")
        print("Топ протоколов:")
        for proto, count in self.protocol_counter.most_common(5):
            print(f"  {proto}: {count}")


def main():
    pcap_file = "many_interfaces.pcapng"

    if not os.path.exists(pcap_file):
        print("Файл не найден")
        return

    analyzer = StablePCAPAnalyzer(pcap_file)
    analyzer.analyze()


if __name__ == "__main__":
    main()
