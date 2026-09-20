import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


# Common TCP ports
PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP-Proxy",
}


# Ports that deserve additional attention
RISKY_PORTS = {
    21: "FTP may transmit credentials without encryption.",
    23: "Telnet is insecure and should generally be disabled.",
    139: "NetBIOS may expose Windows networking services.",
    445: "SMB should not be exposed unnecessarily.",
    3389: "RDP should be restricted to trusted networks.",
    5900: "VNC may provide remote desktop access.",
}


def validate_network(network):

    try:
        net = ipaddress.ip_network(
            network,
            strict=False
        )

    except ValueError:
        raise ValueError(
            "Invalid network. Example: 192.168.1.0/24"
        )

    # Only allow private IPv4 networks
    if not net.is_private:
        raise ValueError(
            "For safety, only private networks are allowed."
        )

    # Prevent accidentally huge scans
    if net.num_addresses > 256:
        raise ValueError(
            "Network is too large. Maximum supported size is /24."
        )

    return net


def check_port(ip, port, timeout):

    try:

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(timeout)

        result = sock.connect_ex(
            (str(ip), port)
        )

        sock.close()

        return result == 0

    except Exception:
        return False


def scan_host(ip, timeout):

    ip = str(ip)

    open_ports = []
    services = {}

    for port, service in PORTS.items():

        if check_port(
            ip,
            port,
            timeout
        ):

            open_ports.append(port)
            services[port] = service

    # Device did not respond to any tested port
    if not open_ports:

        return {
            "ip": ip,
            "online": False,
            "open_ports": [],
            "services": {},
            "risk": "Low",
            "warnings": [],
            "recommendations": [
                "No tested TCP services were detected."
            ]
        }

    warnings = []
    recommendations = []

    for port in open_ports:

        if port in RISKY_PORTS:

            warnings.append(
                RISKY_PORTS[port]
            )

    # Recommendations
    if 23 in open_ports:

        recommendations.append(
            "Disable Telnet and use SSH where possible."
        )

    if 21 in open_ports:

        recommendations.append(
            "Prefer SFTP/FTPS instead of plain FTP."
        )

    if 445 in open_ports:

        recommendations.append(
            "Restrict SMB access to trusted devices."
        )

    if 3389 in open_ports:

        recommendations.append(
            "Restrict RDP using firewall/VPN rules."
        )

    if 5900 in open_ports:

        recommendations.append(
            "Restrict VNC access to trusted hosts."
        )

    if not recommendations:

        recommendations.append(
            "Review whether these services need "
            "to be reachable on your network."
        )

    # Risk calculation
    risky_count = sum(
        1 for p in open_ports
        if p in RISKY_PORTS
    )

    if risky_count >= 2:

        risk = "High"

    elif risky_count == 1:

        risk = "Medium"

    else:

        risk = "Low"

    return {
        "ip": ip,
        "online": True,
        "open_ports": open_ports,
        "services": services,
        "risk": risk,
        "warnings": warnings,
        "recommendations": recommendations
    }


def scan_network(network, timeout=0.5):

    try:

        net = validate_network(network)

    except ValueError as e:

        return [], str(e)

    hosts = list(net.hosts())

    results = []

    # Limit concurrency
    with ThreadPoolExecutor(
        max_workers=32
    ) as executor:

        futures = {
            executor.submit(
                scan_host,
                ip,
                timeout
            ): ip

            for ip in hosts
        }

        for future in as_completed(futures):

            try:

                result = future.result()

                if result["online"]:
                    results.append(result)

            except Exception:
                pass

    # Sort IP addresses
    results.sort(
        key=lambda x: ipaddress.ip_address(
            x["ip"]
        )
    )

    return results, None


def calculate_risk(results):

    if not results:
        return 100

    penalty = 0

    for device in results:

        for port in device["open_ports"]:

            if port in RISKY_PORTS:

                penalty += 10

            else:

                penalty += 2

    score = 100 - penalty

    return max(
        0,
        min(100, score)
    )
