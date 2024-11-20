from flask import Flask, render_template, request, send_from_directory
import scapy.all as scapy
import socket
import csv
import os

app = Flask(__name__)

# Directory to save results
RESULTS_DIR = "results"
os.makedirs(RESULTS_DIR, exist_ok=True)


def get_mac(ip):
    """
    Get the MAC address of a device on the network.
    """
    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
        return answered[0][1].hwsrc if answered else None
    except Exception:
        return None


def scan_network(network_prefix):
    """
    Scan the specified network to find active devices.
    """
    devices = []
    for i in range(1, 255):
        ip = f"{network_prefix}.{i}"
        try:
            socket.gethostbyaddr(ip)
            mac_address = get_mac(ip)
            devices.append({"IP Address": ip, "MAC Address": mac_address})
        except socket.herror:
            continue
    return devices


def scan_ports(ip):
    """
    Scan open ports on a given IP address.
    """
    ports = []
    for port in range(1, 1025):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                ports.append(port)
            sock.close()
        except:
            continue
    return ports


def save_results_to_csv(devices, filename):
    """
    Save scan results to a CSV file.
    """
    filepath = os.path.join(RESULTS_DIR, filename)
    with open(filepath, 'w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=["IP Address", "MAC Address"])
        writer.writeheader()
        writer.writerows(devices)
    return filepath


@app.route('/', methods=['GET', 'POST'])
def home():
    devices = []
    ports = []
    error_message = None
    filename = None

    if request.method == 'POST':
        network_prefix = request.form.get('network_prefix')
        ip_for_ports = request.form.get('ip_for_ports')

        if network_prefix:
            try:
                devices = scan_network(network_prefix)
                filename = f"scan_results_{network_prefix}.csv"
                save_results_to_csv(devices, filename)
            except Exception as e:
                error_message = f"Error scanning network: {e}"

        if ip_for_ports:
            try:
                ports = scan_ports(ip_for_ports)
            except Exception as e:
                error_message = f"Error scanning ports: {e}"

    return render_template(
        'home.html',
        devices=devices,
        ports=ports,
        error_message=error_message,
        filename=filename
    )


@app.route('/download/<filename>')
def download_file(filename):
    """
    Route to download the CSV file.
    """
    return send_from_directory(RESULTS_DIR, filename, as_attachment=True)


if __name__ == '__main__':
    app.run(debug=True)
