import streamlit as st
import socket
import ipaddress
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="NetGuard | Network Security Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown("""
<style>

@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

.stApp {
    background:
        radial-gradient(circle at 10% 10%, rgba(37,99,235,0.12), transparent 30%),
        radial-gradient(circle at 90% 20%, rgba(6,182,212,0.08), transparent 25%),
        #080c12;
    color: #f8fafc;
}

/* Main container */
.block-container {
    max-width: 1400px;
    padding-top: 2rem;
    padding-bottom: 3rem;
}

/* Sidebar */
section[data-testid="stSidebar"] {
    background: #0c1119;
    border-right: 1px solid #1f2937;
}

section[data-testid="stSidebar"] h2,
section[data-testid="stSidebar"] h3 {
    color: #f8fafc;
}

/* Hero */
.hero {
    padding: 30px;
    border-radius: 22px;
    border: 1px solid #263244;
    background:
        linear-gradient(135deg, rgba(37,99,235,0.18), rgba(8,12,18,0.85)),
        #101722;
    margin-bottom: 25px;
}

.hero-title {
    font-size: 44px;
    font-weight: 800;
    letter-spacing: -1.5px;
    margin-bottom: 5px;
}

.hero-title span {
    color: #38bdf8;
}

.hero-subtitle {
    color: #94a3b8;
    font-size: 17px;
    max-width: 850px;
    line-height: 1.6;
}

/* Cards */
.card {
    background: rgba(15, 23, 34, 0.95);
    border: 1px solid #263244;
    border-radius: 18px;
    padding: 22px;
    margin-bottom: 16px;
}

.card-title {
    font-size: 18px;
    font-weight: 700;
    margin-bottom: 8px;
}

.card-text {
    color: #94a3b8;
    line-height: 1.6;
}

/* Metric cards */
.metric-card {
    background: #101722;
    border: 1px solid #263244;
    border-radius: 16px;
    padding: 20px;
    text-align: center;
}

.metric-number {
    font-size: 30px;
    font-weight: 800;
}

.metric-label {
    color: #94a3b8;
    font-size: 13px;
    margin-top: 5px;
}

/* Risk badges */
.badge-low {
    color: #22c55e;
    background: rgba(34,197,94,0.12);
    border: 1px solid rgba(34,197,94,0.3);
    padding: 5px 10px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 700;
}

.badge-medium {
    color: #f59e0b;
    background: rgba(245,158,11,0.12);
    border: 1px solid rgba(245,158,11,0.3);
    padding: 5px 10px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 700;
}

.badge-high {
    color: #ef4444;
    background: rgba(239,68,68,0.12);
    border: 1px solid rgba(239,68,68,0.3);
    padding: 5px 10px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 700;
}

.badge-critical {
    color: #f43f5e;
    background: rgba(244,63,94,0.15);
    border: 1px solid rgba(244,63,94,0.4);
    padding: 5px 10px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 700;
}

/* Info boxes */
.info-box {
    background: #101722;
    border-left: 4px solid #38bdf8;
    border-radius: 10px;
    padding: 15px;
    color: #cbd5e1;
    margin: 12px 0;
}

.warning-box {
    background: rgba(245,158,11,0.08);
    border-left: 4px solid #f59e0b;
    border-radius: 10px;
    padding: 15px;
    color: #fbbf24;
    margin: 12px 0;
}

/* Buttons */
.stButton > button {
    border-radius: 10px;
    height: 46px;
    font-weight: 700;
    border: 1px solid #334155;
}

.stButton > button:hover {
    border-color: #38bdf8;
}

/* Tabs */
button[data-baseweb="tab"] {
    font-weight: 600;
}

/* Progress */
div[data-testid="stProgressBar"] > div > div {
    border-radius: 20px;
}

/* Footer */
.footer {
    text-align: center;
    color: #64748b;
    font-size: 12px;
    padding: 30px;
}

</style>
""", unsafe_allow_html=True)


# ============================================================
# PORT DATABASE
# ============================================================

PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP Alternate",
}

RISKY_PORTS = {
    21: (
        "FTP detected",
        "FTP may transmit credentials without encryption.",
        "Consider SFTP or another encrypted file-transfer protocol."
    ),

    23: (
        "Telnet detected",
        "Telnet transmits communication without modern encryption.",
        "Disable Telnet and use SSH where appropriate."
    ),

    139: (
        "NetBIOS detected",
        "Legacy Windows networking services may be exposed.",
        "Restrict NetBIOS access to trusted devices."
    ),

    445: (
        "SMB detected",
        "SMB can expose file-sharing services to other devices.",
        "Restrict SMB access and disable unnecessary file sharing."
    ),

    3389: (
        "RDP detected",
        "Remote Desktop is exposed on this device.",
        "Restrict RDP using firewall rules or a VPN."
    ),

    5900: (
        "VNC detected",
        "Remote desktop access may be available.",
        "Restrict VNC access to trusted devices."
    ),
}


# ============================================================
# SESSION STATE
# ============================================================

if "results" not in st.session_state:
    st.session_state.results = []

if "scan_time" not in st.session_state:
    st.session_state.scan_time = None

if "scanned_network" not in st.session_state:
    st.session_state.scanned_network = ""


# ============================================================
# FUNCTIONS
# ============================================================

def validate_network(network):
    """
    Validate that the target is a private IPv4 network.
    """

    try:
        net = ipaddress.ip_network(
            network,
            strict=False
        )
    except ValueError:
        raise ValueError(
            "Invalid network format. Example: 192.168.1.0/24"
        )

    if net.version != 4:
        raise ValueError(
            "Only IPv4 private networks are supported."
        )

    if not net.is_private:
        raise ValueError(
            "For safety, only private networks can be scanned."
        )

    # Prevent accidentally huge scans
    if net.num_addresses > 256:
        raise ValueError(
            "Network is too large. Use a /24 or smaller network."
        )

    return net


def check_port(ip, port, timeout):
    """
    Check whether a TCP port accepts a connection.
    """

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.settimeout(timeout)

    try:
        result = sock.connect_ex(
            (str(ip), port)
        )

        return result == 0

    except Exception:
        return False

    finally:
        sock.close()


def scan_host(ip, timeout):
    """
    Scan common TCP ports on one host.
    """

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

    if not open_ports:
        return None

    warnings = []
    recommendations = []

    risky_count = 0

    for port in open_ports:

        if port in RISKY_PORTS:

            risky_count += 1

            title, explanation, recommendation = RISKY_PORTS[port]

            warnings.append(
                f"{title}: {explanation}"
            )

            recommendations.append(
                recommendation
            )

    # Remove duplicate recommendations
    recommendations = list(
        dict.fromkeys(recommendations)
    )

    if risky_count >= 2:
        risk = "High"

    elif risky_count == 1:
        risk = "Medium"

    else:
        risk = "Low"

    return {
        "ip": str(ip),
        "online": True,
        "open_ports": open_ports,
        "services": services,
        "risk": risk,
        "warnings": warnings,
        "recommendations": recommendations
    }


def scan_network(network, timeout, progress_callback=None):

    net = validate_network(network)

    hosts = list(net.hosts())

    results = []

    completed = 0

    total = len(hosts)

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

            completed += 1

            if progress_callback:
                progress_callback(
                    completed / total
                )

            try:
                result = future.result()

                if result:
                    results.append(result)

            except Exception:
                pass

    results.sort(
        key=lambda x: ipaddress.ip_address(
            x["ip"]
        )
    )

    return results


def calculate_score(results):

    if not results:
        return 100

    score = 100

    for device in results:

        for port in device["open_ports"]:

            if port in RISKY_PORTS:
                score -= 10

            else:
                score -= 2

    return max(
        0,
        min(100, score)
    )


def get_score_status(score):

    if score >= 80:
        return "Low Risk", "🟢"

    elif score >= 50:
        return "Medium Risk", "🟡"

    elif score >= 25:
        return "High Risk", "🟠"

    return "Critical Risk", "🔴"


def get_risk_badge(risk):

    if risk == "Low":
        return '<span class="badge-low">LOW</span>'

    if risk == "Medium":
        return '<span class="badge-medium">MEDIUM</span>'

    if risk == "High":
        return '<span class="badge-high">HIGH</span>'

    return '<span class="badge-critical">CRITICAL</span>'


def generate_report():

    results = st.session_state.results

    score = calculate_score(results)

    report = {
        "application": "NetGuard",
        "scan_time": st.session_state.scan_time,
        "network": st.session_state.scanned_network,
        "security_score": score,
        "devices_found": len(results),
        "devices": results
    }

    return json.dumps(
        report,
        indent=4
    )


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.markdown("## 🛡️ NetGuard")

    st.caption(
        "Home & Campus Network Security Scanner"
    )

    st.markdown("---")

    st.markdown("### ⚙️ Scan Configuration")

    network = st.text_input(
        "Private Network",
        value="192.168.1.0/24",
        help="Example: 192.168.1.0/24"
    )

    timeout = st.slider(
        "Port Timeout",
        min_value=0.1,
        max_value=2.0,
        value=0.5,
        step=0.1
    )

    st.markdown("---")

    st.markdown("### 🔍 Scan Checks")

    st.checkbox(
        "Host discovery",
        value=True,
        disabled=True
    )

    st.checkbox(
        "TCP port detection",
        value=True,
        disabled=True
    )

    st.checkbox(
        "Risk analysis",
        value=True,
        disabled=True
    )

    st.checkbox(
        "Recommendations",
        value=True,
        disabled=True
    )

    st.markdown("---")

    st.markdown(
        """
        <div class="warning-box">
        <b>Authorized use only</b><br><br>
        Scan only networks you own or have
        explicit permission to assess.
        </div>
        """,
        unsafe_allow_html=True
    )


# ============================================================
# HERO
# ============================================================

st.markdown("""
<div class="hero">

<div class="hero-title">
🛡️ Net<span>Guard</span>
</div>

<div class="hero-subtitle">
An interactive network security dashboard that discovers
devices and identifies potentially exposed services on an
authorized private network.
</div>

</div>
""", unsafe_allow_html=True)


# ============================================================
# TABS
# ============================================================

tab_dashboard, tab_scanner, tab_findings, tab_about = st.tabs(
    [
        "📊 Dashboard",
        "🔍 Network Scanner",
        "⚠️ Security Findings",
        "ℹ️ About"
    ]
)


# ============================================================
# DASHBOARD
# ============================================================

with tab_dashboard:

    results = st.session_state.results

    score = calculate_score(results)

    status, icon = get_score_status(score)

    devices = len(results)

    total_ports = sum(
        len(device["open_ports"])
        for device in results
    )

    risky_devices = sum(
        1
        for device in results
        if device["risk"] in ["High", "Critical"]
    )

    medium_devices = sum(
        1
        for device in results
        if device["risk"] == "Medium"
    )

    st.markdown("## Security Overview")

    c1, c2, c3, c4 = st.columns(4)

    with c1:

        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-number">{devices}</div>
                <div class="metric-label">DEVICES FOUND</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with c2:

        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-number">{total_ports}</div>
                <div class="metric-label">OPEN PORTS</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with c3:

        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-number">{risky_devices}</div>
                <div class="metric-label">HIGH-RISK DEVICES</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with c4:

        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-number">{score}</div>
                <div class="metric-label">SECURITY SCORE</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown("")

    left, right = st.columns([1, 1])

    with left:

        st.markdown(
            '<div class="card">',
            unsafe_allow_html=True
        )

        st.markdown(
            "### 🔐 Network Security Score"
        )

        st.progress(
            score / 100
        )

        st.markdown(
            f"## {icon} {score}/100"
        )

        st.markdown(
            f"**Current status:** {status}"
        )

        st.markdown(
            """
            <p class="card-text">
            The score is based on the services detected
            during the authorized scan. It is a demonstration
            metric, not a complete security audit.
            </p>
            """,
            unsafe_allow_html=True
        )

        st.markdown(
            '</div>',
            unsafe_allow_html=True
        )

    with right:

        st.markdown(
            '<div class="card">',
            unsafe_allow_html=True
        )

        st.markdown(
            "### 📡 Scan Information"
        )

        if st.session_state.scan_time:

            st.write(
                f"**Last scan:** "
                f"{st.session_state.scan_time}"
            )

            st.write(
                f"**Network:** "
                f"`{st.session_state.scanned_network}`"
            )

        else:

            st.write(
                "No scan has been performed yet."
            )

        st.markdown(
            """
            <p class="card-text">
            Start a scan from the Network Scanner tab
            to populate this dashboard.
            </p>
            """,
            unsafe_allow_html=True
        )

        st.markdown(
            '</div>',
            unsafe_allow_html=True
        )

    # Risk distribution

    st.markdown("### 📈 Risk Distribution")

    r1, r2, r3, r4 = st.columns(4)

    low_count = sum(
        1 for x in results
        if x["risk"] == "Low"
    )

    with r1:
        st.metric(
            "🟢 Low",
            low_count
        )

    with r2:
        st.metric(
            "🟡 Medium",
            medium_devices
        )

    with r3:
        st.metric(
            "🔴 High",
            risky_devices
        )

    with r4:
        st.metric(
            "📡 Total",
            devices
        )


# ============================================================
# SCANNER
# ============================================================

with tab_scanner:

    st.markdown("## 🔍 Network Scanner")

    st.markdown(
        """
        <div class="info-box">
        <b>How it works:</b><br>
        NetGuard checks common TCP ports on devices in the
        selected private network and analyzes potentially
        risky services.
        </div>
        """,
        unsafe_allow_html=True
    )

    col1, col2 = st.columns([3, 1])

    with col1:

        scan_network_input = st.text_input(
            "Network to scan",
            value=network,
            key="scanner_network"
        )

    with col2:

        st.write("")
        st.write("")

        start_scan = st.button(
            "🚀 Start Scan",
            use_container_width=True,
            type="primary"
        )

    if start_scan:

        progress = st.progress(
            0,
            text="Initializing scanner..."
        )

        status_text = st.empty()

        try:

            status_text.info(
                "Validating private network..."
            )

            time.sleep(0.3)

            results = scan_network(
                scan_network_input,
                timeout,
                progress_callback=lambda value:
                    progress.progress(
                        value,
                        text=f"Scanning hosts... {int(value * 100)}%"
                    )
            )

            st.session_state.results = results

            st.session_state.scan_time = (
                datetime.now().strftime(
                    "%d %b %Y, %I:%M:%S %p"
                )
            )

            st.session_state.scanned_network = (
                scan_network_input
            )

            progress.progress(
                1.0,
                text="Scan complete!"
            )

            status_text.success(
                f"Scan completed — {len(results)} active device(s) detected."
            )

            time.sleep(0.5)

            st.rerun()

        except ValueError as e:

            progress.empty()

            st.error(
                str(e)
            )

        except Exception as e:

            progress.empty()

            st.error(
                f"Scanner error: {e}"
            )

    # Current results

    results = st.session_state.results

    if results:

        st.markdown("---")

        st.markdown(
            f"### 🖥️ Discovered Devices — {len(results)}"
        )

        for device in results:

            risk = device["risk"]

            with st.expander(
                f"📡 {device['ip']}   •   {risk} Risk",
                expanded=False
            ):

                a, b, c = st.columns(3)

                with a:

                    st.markdown("**IP Address**")
                    st.code(device["ip"])

                with b:

                    st.markdown("**Risk Level**")

                    st.markdown(
                        get_risk_badge(risk),
                        unsafe_allow_html=True
                    )

                with c:

                    st.markdown("**Open Ports**")
                    st.metric(
                        "Ports",
                        len(device["open_ports"])
                    )

                st.markdown("---")

                if device["open_ports"]:

                    st.markdown("#### 🔓 Detected Services")

                    port_cols = st.columns(
                        min(
                            len(device["open_ports"]),
                            4
                        )
                    )

                    for index, port in enumerate(
                        device["open_ports"]
                    ):

                        with port_cols[
                            index % len(port_cols)
                        ]:

                            service = device[
                                "services"
                            ][port]

                            st.markdown(
                                f"""
                                <div class="card">
                                <b>Port {port}</b><br>
                                {service}
                                </div>
                                """,
                                unsafe_allow_html=True
                            )

                if device["warnings"]:

                    st.markdown(
                        "#### ⚠️ Findings"
                    )

                    for warning in device["warnings"]:

                        st.warning(
                            warning
                        )

                if device["recommendations"]:

                    st.markdown(
                        "#### 💡 Recommendations"
                    )

                    for recommendation in device[
                        "recommendations"
                    ]:

                        st.write(
                            f"→ {recommendation}"
                        )

    else:

        st.markdown(
            """
            <div class="card">

            ### 👋 Ready to scan

            Enter an authorized private network and
            click **Start Scan**.

            Example:

            `192.168.1.0/24`

            </div>
            """,
            unsafe_allow_html=True
        )


# ============================================================
# FINDINGS
# ============================================================

with tab_findings:

    st.markdown("## ⚠️ Security Findings")

    results = st.session_state.results

    if not results:

        st.info(
            "Run a network scan to generate security findings."
        )

    else:

        findings = []

        for device in results:

            for port in device["open_ports"]:

                if port in RISKY_PORTS:

                    title, explanation, recommendation = (
                        RISKY_PORTS[port]
                    )

                    findings.append({
                        "ip": device["ip"],
                        "port": port,
                        "service": PORTS[port],
                        "title": title,
                        "explanation": explanation,
                        "recommendation": recommendation
                    })

        if not findings:

            st.success(
                "No specifically flagged services were detected."
            )

            st.markdown(
                """
                This does not mean the network is completely
                secure. NetGuard performs a limited scan of
                selected TCP services.
                """
            )

        else:

            st.markdown(
                f"**{len(findings)} potential finding(s) detected.**"
            )

            for finding in findings:

                st.markdown(
                    f"""
                    <div class="card">

                    <div class="card-title">
                    ⚠️ {finding['title']}
                    </div>

                    <p>
                    <b>Device:</b> {finding['ip']}<br>
                    <b>Port:</b> {finding['port']}<br>
                    <b>Service:</b> {finding['service']}
                    </p>

                    <p class="card-text">
                    {finding['explanation']}
                    </p>

                    <p>
                    <b>💡 Recommendation:</b>
                    {finding['recommendation']}
                    </p>

                    </div>
                    """,
                    unsafe_allow_html=True
                )


# ============================================================
# ABOUT
# ============================================================

with tab_about:

    st.markdown("## ℹ️ About NetGuard")

    st.markdown(
        """
        <div class="card">

        ### 🎯 Problem

        Home, hostel and campus networks can contain routers,
        computers, cameras and IoT devices with unnecessary
        network services exposed.

        ### 💡 Solution

        NetGuard provides a simple dashboard for identifying
        devices and common TCP services on an authorized
        private network.

        ### 🔎 What it checks

        - Active devices
        - Common TCP ports
        - Potentially risky services
        - Basic risk classification
        - Security recommendations

        ### 🧠 Technology

        **Python + Streamlit + Socket Programming +
        Concurrent Network Scanning**

        </div>
        """,
        unsafe_allow_html=True
    )

    st.markdown("### 🚫 What NetGuard does NOT do")

    x1, x2, x3 = st.columns(3)

    with x1:
        st.markdown(
            """
            <div class="card">
            🔐<br><br>
            <b>No Password Attacks</b><br>
            <span class="card-text">
            NetGuard does not guess or attempt credentials.
            </span>
            </div>
            """,
            unsafe_allow_html=True
        )

    with x2:
        st.markdown(
            """
            <div class="card">
            💥<br><br>
            <b>No Exploitation</b><br>
            <span class="card-text">
            It does not exploit detected services.
            </span>
            </div>
            """,
            unsafe_allow_html=True
        )

    with x3:
        st.markdown(
            """
            <div class="card">
            🛑<br><br>
            <b>No DoS Testing</b><br>
            <span class="card-text">
            It does not perform disruptive traffic tests.
            </span>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown("### 📥 Export Scan Report")

    if st.session_state.results:

        report = generate_report()

        st.download_button(
            label="⬇️ Download JSON Security Report",
            data=report,
            file_name="netguard_security_report.json",
            mime="application/json",
            use_container_width=True
        )

    else:

        st.info(
            "Run a scan first to generate a report."
        )


# ============================================================
# FOOTER
# ============================================================

st.markdown(
    """
    <div class="footer">
    🛡️ NetGuard — Network Security Demonstration Project
    <br>
    Scan only networks you are authorized to test.
    </div>
    """,
    unsafe_allow_html=True
)
