import streamlit as st
from scanner import scan_network, calculate_risk

st.set_page_config(
    page_title="NetGuard",
    page_icon="🛡️",
    layout="wide"
)

# -----------------------------
# Custom CSS
# -----------------------------
st.markdown("""
<style>
    .main {
        background-color: #0b0f14;
    }

    .block-container {
        padding-top: 2rem;
    }

    .title {
        font-size: 42px;
        font-weight: 800;
        color: #ffffff;
    }

    .subtitle {
        color: #9ca3af;
        font-size: 17px;
        margin-bottom: 30px;
    }

    .card {
        background: #151b23;
        border: 1px solid #29313d;
        padding: 20px;
        border-radius: 15px;
        margin-bottom: 15px;
    }

    .safe {
        color: #22c55e;
        font-weight: bold;
    }

    .warning {
        color: #f59e0b;
        font-weight: bold;
    }

    .danger {
        color: #ef4444;
        font-weight: bold;
    }

    .info {
        color: #3b82f6;
        font-weight: bold;
    }

    .stButton > button {
        width: 100%;
        border-radius: 10px;
        height: 45px;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)


# -----------------------------
# Header
# -----------------------------
st.markdown(
    '<div class="title">🛡️ NetGuard</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">'
    'Home & Campus Network Vulnerability Scanner'
    '</div>',
    unsafe_allow_html=True
)

st.info(
    "⚠️ Scan only networks and devices you own or have explicit permission to test."
)


# -----------------------------
# Sidebar
# -----------------------------
with st.sidebar:

    st.header("⚙️ Scan Settings")

    network = st.text_input(
        "Private Network",
        value="192.168.1.0/24",
        help="Example: 192.168.1.0/24"
    )

    timeout = st.slider(
        "Connection Timeout",
        min_value=0.1,
        max_value=2.0,
        value=0.5,
        step=0.1
    )

    st.markdown("---")

    st.markdown("### 🔍 What we check")

    st.checkbox("Open TCP ports", value=True, disabled=True)
    st.checkbox("Common risky services", value=True, disabled=True)
    st.checkbox("Security score", value=True, disabled=True)

    st.markdown("---")

    st.caption(
        "NetGuard performs non-authenticated network checks. "
        "It does not attempt passwords or exploit devices."
    )


# -----------------------------
# Main dashboard
# -----------------------------

if "results" not in st.session_state:
    st.session_state.results = []


if st.button("🚀 Start Network Scan"):

    with st.spinner("Scanning authorized private network..."):

        results, message = scan_network(
            network,
            timeout
        )

        st.session_state.results = results

        if message:
            st.error(message)


results = st.session_state.results


# -----------------------------
# Results
# -----------------------------

if results:

    score = calculate_risk(results)

    total_hosts = len(results)

    vulnerable_hosts = sum(
        1 for x in results
        if x["risk"] in ["High", "Critical"]
    )

    open_ports = sum(
        len(x["open_ports"])
        for x in results
    )

    # Metrics
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            "Hosts Found",
            total_hosts
        )

    with col2:
        st.metric(
            "Open Ports",
            open_ports
        )

    with col3:
        st.metric(
            "High Risk Hosts",
            vulnerable_hosts
        )

    with col4:
        st.metric(
            "Security Score",
            f"{score}/100"
        )

    st.markdown("---")

    # Security score
    st.subheader("🔐 Network Security Score")

    st.progress(score / 100)

    if score >= 80:
        st.markdown(
            '<p class="safe">🟢 Low Risk</p>',
            unsafe_allow_html=True
        )

    elif score >= 50:
        st.markdown(
            '<p class="warning">🟡 Medium Risk</p>',
            unsafe_allow_html=True
        )

    else:
        st.markdown(
            '<p class="danger">🔴 High Risk</p>',
            unsafe_allow_html=True
        )

    # -----------------------------
    # Host table
    # -----------------------------

    st.subheader("🖥️ Discovered Devices")

    for device in results:

        if device["risk"] == "Critical":
            risk_class = "danger"

        elif device["risk"] == "High":
            risk_class = "danger"

        elif device["risk"] == "Medium":
            risk_class = "warning"

        else:
            risk_class = "safe"

        with st.expander(
            f"📡 {device['ip']} — {device['risk']} Risk"
        ):

            c1, c2 = st.columns(2)

            with c1:
                st.write("**IP Address:**", device["ip"])
                st.write(
                    "**Response:**",
                    "Online" if device["online"] else "No response"
                )

            with c2:
                st.markdown(
                    f"**Risk:** "
                    f'<span class="{risk_class}">'
                    f'{device["risk"]}'
                    f'</span>',
                    unsafe_allow_html=True
                )

            st.markdown("### 🔓 Open Ports")

            if device["open_ports"]:

                for port in device["open_ports"]:

                    service = device["services"].get(
                        port,
                        "Unknown"
                    )

                    st.write(
                        f"• `{port}` — {service}"
                    )

            else:
                st.success("No tested ports were open.")

            if device["warnings"]:

                st.markdown("### ⚠️ Security Findings")

                for warning in device["warnings"]:
                    st.warning(warning)

            st.markdown("### 💡 Recommendation")

            for recommendation in device["recommendations"]:
                st.write(f"→ {recommendation}")


else:

    st.markdown("""
    <div class="card">

    ### 👋 Welcome to NetGuard

    Enter an authorized private network above and start a scan.

    **Example**

    `192.168.1.0/24`

    NetGuard will look for:

    - 🖥️ Active hosts
    - 🔓 Common open TCP ports
    - ⚠️ Potentially risky services
    - 📊 Overall security score
    - 💡 Plain-English recommendations

    </div>
    """, unsafe_allow_html=True)
