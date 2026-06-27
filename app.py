
import streamlit as st
import pandas as pd
from pymongo import MongoClient
import datetime
from ti_aggregator import ThreatIntelligenceAggregator
from policy_enforcer import DynamicPolicyEnforcer
import config


st.set_page_config(page_title="Financial Infrastructure Threat Intelligence Platform", layout="wide")
st.title("🛡️ Institutional Threat Intelligence Platform & Automated Enforcer")
st.markdown("---")


aggregator = ThreatIntelligenceAggregator()
enforcer = DynamicPolicyEnforcer()
client = MongoClient(config.MONGO_URI)
db = client[config.DB_NAME]


st.sidebar.header("Operational Action Center")
if st.sidebar.button("Run OSINT Ingestion Cycle"):
    with st.spinner("Executing extraction routines across network vectors..."):
        aggregator.aggregate_and_normalize()
    st.sidebar.success("Ingestion and structural deduplication routine completed successfully.")

if st.sidebar.button("Execute Dynamic Policy Enforcement"):
    with st.spinner("Scanning inventory data and writing new iptables filters..."):
        enforcer.enforce_high_risk_policies()
    st.sidebar.success("Policy enforcement engine synchronization completed.")


col1, col2, col3, col4 = st.columns(4)
total_iocs = db[config.IOC_COLLECTION].count_documents({})
active_blocks = db[config.POLICY_LOG_COLLECTION].count_documents({"action": "BLOCK"})
active_rollbacks = db[config.POLICY_LOG_COLLECTION].count_documents({"action": "ROLLBACK"})

with col1:
    st.metric(label="Total Aggregated IoCs", value=total_iocs)
with col2:
    st.metric(label="Autonomous Active Firewall Rules", value=active_blocks)
with col3:
    st.metric(label="Manual Operator Rollbacks", value=active_rollbacks)
with col4:
    st.metric(label="System Enforcement Cutoff Threshold", value=f"Score >= {config.AUTOMATED_BLOCK_THRESHOLD}")

st.markdown("### Normalized Threat Intelligence Inventory Matrix")
ioc_cursor = db[config.IOC_COLLECTION].find().sort("risk_score", -1)
ioc_list = list(ioc_cursor)

if ioc_list:
    df_iocs = pd.DataFrame(ioc_list).drop(columns=["_id"])
    st.dataframe(df_iocs, use_container_width=True)
else:
    st.info("No threat data located. Trigger ingestion processing pipeline from panel menu layout.")

st.markdown("### System Enforcement Logs & Network Rule State")
log_cursor = db[config.POLICY_LOG_COLLECTION].find().sort("timestamp", -1)
log_list = list(log_cursor)

if log_list:
    df_logs = pd.DataFrame(log_list).drop(columns=["_id"])
    st.dataframe(df_logs, use_container_width=True)
else:
    st.info("No network architecture operations executed on system firewalls.")

st.markdown("### SOC Analyst Incident Response Remediation Console")
st.markdown("If a false positive compromises production transactional applications, enter the target IP vector below to instantly execute network rule removal.")

target_rollback_ip = st.text_input("Target Network Vector for Reversion Action (IPv4 Address)")
analyst_sig = st.text_input("Authorized Signature Field", value="SOC_ANALYST_ALPHA")

if st.button("Authorize Mandatory Policy Rollback"):
    if target_rollback_ip:
        # Check if record has active policy entries
        match = db[config.POLICY_LOG_COLLECTION].find_one({"indicator": target_rollback_ip, "action": "BLOCK"})
        if match:
            with st.spinner("Removing network filter rules..."):
                success = enforcer.rollback_policy(target_rollback_ip, analyst_name=analyst_sig)
            if success:
                st.success(f"Successfully removed operational firewall blocking filter for target: {target_rollback_ip}. Core connection verified.")
                st.rerun()
        else:
            st.error("Target address entered has no verifiable operational constraints active within host subsystem firewalls.")
    else:
        st.warning("Input operational validation parameters before attempting access control overrides.")