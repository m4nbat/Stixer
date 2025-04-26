# Streamlit STIX 2.1 Visualizer and Editor
# -----------------------------------------
# STEP 8 (Moved Remove Button): Move Remove Element section to main page.
# Requirements:
#   pip install streamlit stix2 st-cytoscape
#
# Run: python -m streamlit run your_script_name.py

import streamlit as st
from stix2 import Bundle, parse
import uuid
import json
from st_cytoscape import cytoscape
import base64
import os
import re # Import regex for splitting lists

# --- Configuration ---
st.set_page_config(layout="wide")

# --- Original Light Theme Styling ---
st.markdown("""
<style>
body {
    background-color: #f0f0f0; /* Original light grey background */
}
.block-container {
    padding: 2rem;
}
.sidebar .sidebar-content {
    background-color: #f0f0f0; /* Match body background */
}
.stTextArea textarea {
    font-family: monospace; /* Use monospace for list inputs */
    height: 100px; /* Adjust height for list inputs */
}
/* Ensure cytoscape div takes available space */
.stCytoscape > div {
    width: 100%;
    height: 100%;
}
/* Selected node display (used in main area now) */
.selected-node-main {
    border: 1px solid #ddd; /* Light border */
    border-radius: 5px;
    padding: 5px 10px;
    margin: 5px 0; /* Add vertical margin */
    background-color: #e9ecef; /* Light grey background */
    color: #0e1117; /* Dark text for readability */
    display: inline-block; /* Allow multiple selections side-by-side */
    margin-right: 5px; /* Space between selections */
}
.selected-node-label-main {
    font-weight: bold;
    margin-right: 5px;
    color: #007bff; /* Blue accent */
}
/* Ensure alert text is readable */
.stAlert p {
     color: #0e1117; /* Default dark text */
}
/* Container for removal section */
.remove-container {
    border: 1px dashed #ccc;
    border-radius: 5px;
    padding: 1rem;
    margin-top: 1rem;
    margin-bottom: 1rem;
}

</style>
""", unsafe_allow_html=True)


# --- Hardcoded Relationship Rules ---
HARDCODED_VALID_RELATIONSHIPS = {
    ('attack-pattern', 'malware'): ['delivers', 'uses'],
    ('attack-pattern', 'identity'): ['targets'],
    ('attack-pattern', 'location'): ['targets'],
    ('attack-pattern', 'vulnerability'): ['targets'],
    ('attack-pattern', 'tool'): ['uses'],
    ('campaign', 'intrusion-set'): ['attributed-to'],
    ('campaign', 'threat-actor'): ['attributed-to'],
    ('campaign', 'infrastructure'): ['compromises', 'uses'],
    ('campaign', 'location'): ['originates-from', 'targets'],
    ('campaign', 'identity'): ['targets'],
    ('campaign', 'vulnerability'): ['targets'],
    ('campaign', 'attack-pattern'): ['uses'],
    ('campaign', 'malware'): ['uses'],
    ('course-of-action', 'indicator'): ['investigates', 'mitigates'],
    ('course-of-action', 'attack-pattern'): ['mitigates'],
    ('course-of-action', 'malware'): ['mitigates'],
    ('course-of-action', 'tool'): ['mitigates'],
    ('course-of-action', 'vulnerability'): ['mitigates'],
    ('identity', 'location'): ['located-at'],
    ('indicator', 'attack-pattern'): ['indicates'],
    ('indicator', 'campaign'): ['indicates'],
    ('indicator', 'infrastructure'): ['indicates'],
    ('indicator', 'intrusion-set'): ['indicates'],
    ('indicator', 'malware'): ['indicates'],
    ('indicator', 'threat-actor'): ['indicates'],
    ('indicator', 'tool'): ['indicates'],
    ('indicator', 'observed-data'): ['based-on'],
    ('infrastructure', 'infrastructure'): ['communicates-with', 'consists-of', 'controls', 'uses'],
    ('infrastructure', 'ipv4-addr'): ['communicates-with'],
    ('infrastructure', 'ipv6-addr'): ['communicates-with'],
    ('infrastructure', 'domain-name'): ['communicates-with'],
    ('infrastructure', 'url'): ['communicates-with'],
    ('infrastructure', 'observed-data'): ['consists-of'],
    ('infrastructure', 'malware'): ['controls', 'delivers', 'hosts'],
    ('infrastructure', 'vulnerability'): ['has'],
    ('infrastructure', 'tool'): ['hosts'],
    ('infrastructure', 'location'): ['located-at'],
    ('intrusion-set', 'threat-actor'): ['attributed-to'],
    ('intrusion-set', 'infrastructure'): ['compromises', 'hosts', 'owns', 'uses'],
    ('intrusion-set', 'location'): ['originates-from', 'targets'],
    ('intrusion-set', 'vulnerability'): ['targets'],
    ('intrusion-set', 'identity'): ['targets'],
    ('intrusion-set', 'attack-pattern'): ['uses'],
    ('intrusion-set', 'malware'): ['uses'],
    ('intrusion-set', 'tool'): ['uses'],
    ('malware', 'threat-actor'): ['authored-by'],
    ('malware', 'intrusion-set'): ['authored-by'],
    ('malware', 'infrastructure'): ['beacons-to', 'exfiltrate-to', 'targets', 'uses'],
    ('malware', 'url'): ['communicates-with'],
    ('malware', 'domain-name'): ['communicates-with'],
    ('malware', 'ipv6-addr'): ['communicates-with'],
    ('malware', 'ipv4-addr'): ['communicates-with'],
    ('malware', 'malware'): ['controls', 'downloads', 'drops', 'uses', 'variant-of'],
    ('malware', 'tool'): ['downloads', 'drops', 'uses'],
    ('malware', 'file'): ['downloads', 'drops'],
    ('malware', 'vulnerability'): ['exploits', 'targets'],
    ('malware', 'location'): ['originates-from', 'targets'],
    ('malware', 'identity'): ['targets'],
    ('malware', 'attack-pattern'): ['uses'],
    ('malware-analysis', 'malware'): ['characterizes', 'analysis-of', 'static-analysis-of', 'dynamic-analysis-of'],
    ('threat-actor', 'identity'): ['attributed-to', 'impersonates', 'targets'],
    ('threat-actor', 'infrastructure'): ['compromises', 'owns', 'hosts', 'uses'],
    ('threat-actor', 'location'): ['located-at', 'targets'],
    ('threat-actor', 'vulnerability'): ['targets'],
    ('threat-actor', 'attack-pattern'): ['uses'],
    ('threat-actor', 'malware'): ['uses'],
    ('threat-actor', 'tool'): ['uses'],
    ('tool', 'malware'): ['delivers', 'drops'],
    ('tool', 'vulnerability'): ['has', 'targets'],
    ('tool', 'identity'): ['targets'],
    ('tool', 'infrastructure'): ['targets'],
    ('tool', 'location'): ['targets'],
}
# print(f"Using {len(HARDCODED_VALID_RELATIONSHIPS)} updated hardcoded relationship mappings.")

# --- Vocabularies ---
THREAT_ACTOR_TYPES_OV = ["", "activist", "competitor", "crime-syndicate", "criminal", "hacker", "insider-accidental", "insider-disgruntled", "nation-state", "sensationalist", "spy", "terrorist", "unknown"]
THREAT_ACTOR_ROLES_OV = ["", "agent", "director", "independent", "infrastructure-architect", "infrastructure-operator", "malware-author", "sponsor"]
THREAT_ACTOR_SOPHISTICATION_OV = ["", "none", "minimal", "intermediate", "advanced", "expert", "innovator", "strategic"]
ATTACK_RESOURCE_LEVEL_OV = ["", "individual", "club", "contest", "team", "organization", "government"]
ATTACK_MOTIVATION_OV = ["", "accidental", "coercion", "dominance", "ideology", "notoriety", "organizational-gain", "personal-gain", "personal-satisfaction", "revenge", "unpredictable"]
HASH_ALGO_OV = ["", "MD5", "SHA-1", "SHA-256", "SHA-512", "SHA3-256", "SHA3-512", "SSDEEP", "TLSH"]
IDENTITY_CLASS_OV = ["", "individual", "group", "system", "organization", "class", "unknown"]
INDICATOR_TYPES_OV = ["", "anomalous-activity", "anonymization", "benign", "compromised", "malicious-activity", "attribution", "unknown"]
MALWARE_TYPES_OV = ["", "adware", "backdoor", "bot", "bootkit", "ddos", "downloader", "dropper", "exploit-kit", "keylogger", "ransomware", "remote-access-trojan", "resource-exploitation", "rootkit", "screen-capture", "spyware", "trojan", "unknown", "virus", "webshell", "wiper", "worm"]
REPORT_TYPES_OV = ["", "attack-pattern", "campaign", "identity", "indicator", "intrusion-set", "malware", "observed-data", "threat-actor", "threat-report", "tool", "vulnerability"]
TOOL_TYPES_OV = ["", "denial-of-service", "exploitation", "information-gathering", "network-capture", "penetration-testing", "remote-access", "vulnerability-scanning", "unknown"]
REGION_OV = ["", "africa", "eastern-africa", "middle-africa", "northern-africa", "southern-africa", "western-africa", "americas", "latin-america-caribbean", "south-america", "caribbean", "central-america", "northern-america", "asia", "central-asia", "eastern-asia", "southern-asia", "south-eastern-asia", "western-asia", "europe", "eastern-europe", "northern-europe", "southern-europe", "western-europe", "oceania", "antarctica", "australia-new-zealand", "melanesia", "micronesia", "polynesia"]


# --- Helper Functions ---

def get_object_type_from_id(stix_id):
    """Extracts the object type from a STIX ID."""
    if isinstance(stix_id, str) and '--' in stix_id:
        return stix_id.split('--')[0]
    return None

# Robust remove_element function
def remove_element(element_id):
    """Removes an element and its connected relationships from session state."""
    original_obj_count = len(st.session_state.objects)
    obj_to_remove = next((o for o in st.session_state.objects if o['id'] == element_id), None)
    if not obj_to_remove:
        print(f"Element {element_id} not found in objects.")
        return
    rels_to_remove_ids = set()
    if obj_to_remove['type'] == 'relationship':
        rels_to_remove_ids.add(element_id)
        st.session_state.edges = [e for e in st.session_state.edges if e['data']['id'] != element_id]
    else: # Node type object
        connected_rels = [o['id'] for o in st.session_state.objects
                          if o.get('type') == 'relationship' and
                             (o.get('source_ref') == element_id or o.get('target_ref') == element_id)]
        rels_to_remove_ids.update(connected_rels)
        st.session_state.nodes = [n for n in st.session_state.nodes if n['data']['id'] != element_id]
        st.session_state.edges = [e for e in st.session_state.edges if e['data']['id'] not in rels_to_remove_ids]

    st.session_state.objects = [o for o in st.session_state.objects if o['id'] != element_id]
    if obj_to_remove['type'] != 'relationship' and rels_to_remove_ids:
         st.session_state.objects = [o for o in st.session_state.objects if o['id'] not in rels_to_remove_ids]

    removed_count = original_obj_count - len(st.session_state.objects)
    print(f"Removed element {element_id}. Total objects removed: {removed_count}.")


# Icon loading function
@st.cache_data
def get_icon_data_uri(obj_type):
    """Loads icon file, encodes it, and returns a data URI string."""
    try:
        script_dir = os.path.dirname(__file__)
    except NameError:
        script_dir = os.getcwd()
    icon_file = os.path.join(script_dir, 'icons', f"{obj_type}-round-flat-300-dpi.png")
    fallback_icon_file = os.path.join(script_dir, 'icons', "unknown-round-flat-300-dpi.png")
    icon_to_load = icon_file
    if not os.path.exists(icon_file):
        if os.path.exists(fallback_icon_file): icon_to_load = fallback_icon_file
        else: return None
    try:
        with open(icon_to_load, 'rb') as img_f: img_bytes = img_f.read()
        b64 = base64.b64encode(img_bytes).decode('utf-8')
        return f"url('data:image/png;base64,{b64}')"
    except Exception as e:
        print(f"Error reading icon file {icon_to_load}: {e}")
        return None

# --- Define Object Types ---
source_types = set(k[0] for k in HARDCODED_VALID_RELATIONSHIPS.keys())
target_types = set(k[1] for k in HARDCODED_VALID_RELATIONSHIPS.keys())
hardcoded_types = source_types.union(target_types)
standard_types = [
    'attack-pattern','campaign','course-of-action','identity',
    'indicator','infrastructure','intrusion-set','malware','malware-analysis',
    'observed-data','report','threat-actor','tool','vulnerability',
    'location','note','marking-definition', 'language-content',
    'directory', 'domain-name', 'email-addr', 'email-message', 'file',
    'ipv4-addr', 'ipv6-addr', 'mac-addr', 'mutex', 'network-traffic',
    'process', 'software', 'url', 'user-account', 'windows-registry-key', 'x509-certificate'
]
ALL_OBJECT_TYPES = sorted(list(set(standard_types).union(hardcoded_types)))


# --- Session State Initialization ---
if 'objects' not in st.session_state: st.session_state.objects = []
if 'nodes' not in st.session_state: st.session_state.nodes = []
if 'edges' not in st.session_state: st.session_state.edges = []
if 'current_selection' not in st.session_state: st.session_state.current_selection = None
if 'rel_source_sel' not in st.session_state: st.session_state.rel_source_sel = None
if 'rel_target_sel' not in st.session_state: st.session_state.rel_target_sel = None
if 'add_form_selected_type' not in st.session_state: st.session_state.add_form_selected_type = ALL_OBJECT_TYPES[0]


# --- Main App ---
st.title("STIX 2.1 Visualizer & Editor")

# --- Sidebar ---
with st.sidebar:
    # --- Load Bundle ---
    st.header("Load STIX 2.1 Bundle")
    bundle_file = st.file_uploader("Upload STIX 2.1 JSON bundle", type=["json"])
    if bundle_file:
        try:
            # Reset state
            st.session_state.objects = []
            st.session_state.nodes = []
            st.session_state.edges = []
            st.session_state.current_selection = None
            st.session_state.rel_source_sel = None
            st.session_state.rel_target_sel = None
            st.session_state.add_form_selected_type = ALL_OBJECT_TYPES[0]

            bundle_content_bytes = bundle_file.getvalue()
            if not bundle_content_bytes:
                 st.error("Error: Uploaded file is empty.")
                 st.stop()

            try: bundle_content_str = bundle_content_bytes.decode('utf-8-sig')
            except UnicodeDecodeError:
                try: bundle_content_str = bundle_content_bytes.decode('utf-8')
                except UnicodeDecodeError as decode_e:
                    st.error(f"Error decoding file content: {decode_e}.")
                    st.stop()

            try: bundle_json = json.loads(bundle_content_str)
            except json.JSONDecodeError as json_e:
                 st.error(f"Error decoding JSON: {json_e}")
                 st.stop()
            except Exception as read_e:
                 st.error(f"Error loading JSON data: {read_e}")
                 st.stop()

            try: bundle = parse(bundle_json, allow_custom=True)
            except Exception as parse_e:
                 st.error(f"Error parsing STIX bundle: {parse_e}")
                 st.stop()

            temp_nodes, temp_edges, temp_objects = [], [], []
            for i, obj in enumerate(bundle.objects):
                try:
                    if not hasattr(obj, 'id') or not hasattr(obj, 'type'):
                        st.warning(f"Skipping object #{i+1}: missing 'id' or 'type' attribute.")
                        continue
                    obj_dict = json.loads(obj.serialize())
                    temp_objects.append(obj_dict)
                    obj_type = obj_dict['type']
                    obj_id = obj_dict['id']
                    if obj_type == 'relationship':
                        if 'source_ref' in obj_dict and 'target_ref' in obj_dict and 'relationship_type' in obj_dict:
                            temp_edges.append({'data': {'id': obj_id, 'source': obj_dict['source_ref'], 'target': obj_dict['target_ref'], 'label': obj_dict['relationship_type']}})
                        else: st.warning(f"Skipping relationship {obj_id}: missing refs/type.")
                    else:
                        label = obj_dict.get('name', obj_dict.get('value', obj_id))
                        temp_nodes.append({'data': {'id': obj_id, 'label': label}})
                except Exception as obj_proc_e:
                     st.error(f"Error processing object #{i+1} (ID: {getattr(obj, 'id', 'N/A')}): {obj_proc_e}")

            st.session_state.objects = temp_objects
            st.session_state.nodes = temp_nodes
            st.session_state.edges = temp_edges
            st.success(f"Successfully loaded {len(st.session_state.objects)} objects ({len(temp_nodes)} nodes, {len(temp_edges)} edges).")
            st.rerun()
        except Exception as e:
            st.error(f"An unexpected error occurred during bundle loading: {e}")


    # --- Add Object ---
    st.header("Add STIX Object")

    # --- Object Type Selection (Outside Form) ---
    def update_add_form_type():
        st.session_state.add_form_selected_type = st.session_state.add_obj_type_select_widget

    current_add_type_index = 0
    if st.session_state.add_form_selected_type in ALL_OBJECT_TYPES:
        current_add_type_index = ALL_OBJECT_TYPES.index(st.session_state.add_form_selected_type)

    obj_type_selection = st.selectbox(
        "Object Type", ALL_OBJECT_TYPES,
        key="add_obj_type_select_widget", index=current_add_type_index,
        on_change=update_add_form_type
        )
    obj_type = st.session_state.add_form_selected_type # Use type from state

    # --- Form for Object Details ---
    with st.form("add_object_detail_form"):

        # --- Common and Required Fields ---
        name_required = obj_type in ['intrusion-set', 'threat-actor', 'malware', 'tool', 'vulnerability', 'campaign', 'identity', 'location', 'course-of-action', 'attack-pattern']
        name_label = "Name (Required)" if name_required else "Name / Value (Optional, used as label)"
        name = st.text_input(name_label)
        description = st.text_area("Description (Optional)")

        # --- Initialize all possible field variables ---
        # (Keep initialization block from previous step)
        # Intrusion Set
        is_aliases_str, is_first_seen_str, is_last_seen_str, is_goals_str = "", "", "", ""
        is_resource_level, is_primary_motivation = "", ""
        is_secondary_motivations = []
        # Threat Actor
        ta_threat_actor_types = []
        ta_aliases_str, ta_first_seen_str, ta_last_seen_str, ta_goals_str = "", "", "", ""
        ta_roles, ta_sophistication, ta_resource_level, ta_primary_motivation = [], "", "", ""
        ta_secondary_motivations, ta_personal_motivations = [], []
        # Attack Pattern
        ap_aliases_str, ap_kill_chain_phases_str = "", ""
        # Campaign
        c_aliases_str, c_first_seen_str, c_last_seen_str, c_objective = "", "", "", ""
        # Course of Action
        coa_action_str = ""
        # Identity
        id_identity_class = ""
        id_sectors = []
        id_contact_information = ""
        # Indicator
        ind_indicator_types = []
        ind_pattern_type = ""
        ind_pattern = ""
        ind_valid_from_str = ""
        ind_valid_until_str = ""
        ind_kill_chain_phases_str = ""
        # Infrastructure
        inf_aliases_str, inf_kill_chain_phases_str, inf_first_seen_str, inf_last_seen_str = "", "", "", ""
        inf_infrastructure_types = []
        # Location
        loc_region = ""
        loc_country = ""
        loc_administrative_area = ""
        loc_city = ""
        loc_street_address = ""
        loc_postal_code = ""
        loc_latitude = 0.0
        loc_longitude = 0.0
        loc_precision = 0.0
        # Malware
        mal_malware_types = []
        mal_is_family = False
        mal_aliases_str, mal_kill_chain_phases_str, mal_first_seen_str, mal_last_seen_str = "", "", "", ""
        mal_os_execution_envs_str, mal_architecture_execution_envs_str = "", ""
        mal_implementation_languages_str, mal_capabilities_str = "", ""
        mal_sample_refs_str = ""
        # Note
        note_content = ""
        note_authors_str = ""
        note_object_refs_str = ""
        # Observed Data
        obs_first_observed_str, obs_last_observed_str = "", ""
        obs_number_observed = 1
        obs_objects_str = ""
        obs_object_refs_str = ""
        # Report
        rep_report_types = []
        rep_published_str = ""
        rep_object_refs_str = ""
        # Tool
        t_tool_types = []
        t_aliases_str, t_kill_chain_phases_str, t_tool_version = "", "", ""
        # Vulnerability
        vuln_cvssv2_score = 0.0
        vuln_cvssv3_score = 0.0

        # --- Display fields based on selected obj_type ---
        # (Keep conditional display block from previous step)
        if obj_type == 'attack-pattern':
            st.subheader("Attack Pattern Properties")
            ap_aliases_str = st.text_area("Aliases (Optional, one per line)", key="ap_aliases")
            ap_kill_chain_phases_str = st.text_area("Kill Chain Phases (Optional, e.g., kill_chain_name:phase_name\\n...)", key="ap_kill_chain")
        elif obj_type == 'campaign':
             st.subheader("Campaign Properties")
             c_aliases_str = st.text_area("Aliases (Optional, one per line)", key="c_aliases")
             c_first_seen_str = st.text_input("First Seen (Optional, YYYY-MM-DDTHH:mm:ss.sssZ)", key="c_first_seen")
             c_last_seen_str = st.text_input("Last Seen (Optional, YYYY-MM-DDTHH:mm:ss.sssZ)", key="c_last_seen")
             c_objective = st.text_area("Objective (Optional)", key="c_objective")
        elif obj_type == 'course-of-action':
             st.subheader("Course of Action Properties")
        elif obj_type == 'identity':
             st.subheader("Identity Properties")
             id_identity_class = st.selectbox("Identity Class (Optional)", options=IDENTITY_CLASS_OV, key="id_class")
             id_sectors = st.multiselect("Sectors (Optional)", options=[""], key="id_sectors") # Needs industry-sector-ov vocab
             id_contact_information = st.text_input("Contact Information (Optional)", key="id_contact")
        elif obj_type == 'indicator':
             st.subheader("Indicator Properties")
             ind_indicator_types = st.multiselect("Indicator Types (Optional)", options=INDICATOR_TYPES_OV[1:], key="ind_types")
             ind_pattern_type = st.selectbox("Pattern Type (Required)", options=["stix", "pcre", "sigma", "snort", "suricata", "yara"], key="ind_patt_type") # Common types
             ind_pattern = st.text_area("Pattern (Required)", key="ind_pattern")
             ind_valid_from_str = st.text_input("Valid From (Required, YYYY-MM-DDTHH:mm:ss.sssZ)", key="ind_valid_from")
             ind_valid_until_str = st.text_input("Valid Until (Optional, YYYY-MM-DDTHH:mm:ss.sssZ)", key="ind_valid_until")
             ind_kill_chain_phases_str = st.text_area("Kill Chain Phases (Optional, e.g., kill_chain_name:phase_name\\n...)", key="ind_kill_chain")
        elif obj_type == 'infrastructure':
             st.subheader("Infrastructure Properties")
             inf_infrastructure_types = st.multiselect("Infrastructure Types (Optional)", options=["amplification", "anonymization", "botnet", "command-and-control", "exfiltration", "hosting-malware", "hosting-target-lists", "phishing", "reconnaissance", "staging", "unknown"], key="inf_types") # Example types
             inf_aliases_str = st.text_area("Aliases (Optional, one per line)", key="inf_aliases")
             inf_kill_chain_phases_str = st.text_area("Kill Chain Phases (Optional, e.g., kill_chain_name:phase_name\\n...)", key="inf_kill_chain")
             inf_first_seen_str = st.text_input("First Seen (Optional, YYYY-MM-DDTHH:mm:ss.sssZ)", key="inf_first_seen")
             inf_last_seen_str = st.text_input("Last Seen (Optional, YYYY-MM-DDTHH:mm:ss.sssZ)", key="inf_last_seen")
        elif obj_type == 'intrusion-set':
            st.subheader("Intrusion Set Properties")
            is_aliases_str = st.text_area("Aliases (Optional, one per line)", key="is_aliases")
            is_first_seen_str = st.text_input("First Seen (Optional, YYYY-MM-DDTHH:mm:ss.sssZ)", key="is_first_seen")
            is_last_seen_str = st.text_input("Last Seen (Optional, YYYY-MM-DDTHH:mm:ss.sssZ)", key="is_last_seen")
            is_goals_str = st.text_area("Goals (Optional, one per line)", key="is_goals")
            is_resource_level = st.selectbox("Resource Level (Optional)", options=ATTACK_RESOURCE_LEVEL_OV, key="is_resource_level")
            is_primary_motivation = st.selectbox("Primary Motivation (Optional)", options=ATTACK_MOTIVATION_OV, key="is_primary_motivation")
            is_secondary_motivations = st.multiselect("Secondary Motivations (Optional)", options=ATTACK_MOTIVATION_OV, key="is_secondary_motivations")
        elif obj_type == 'location':
             st.subheader("Location Properties")
             loc_region = st.selectbox("Region (Optional)", options=REGION_OV, key="loc_region")
             loc_country = st.text_input("Country (Optional, ISO 3166-1 alpha-2)", key="loc_country") # Add link/validation?
             loc_administrative_area = st.text_input("Administrative Area (e.g., state, province) (Optional)", key="loc_admin_area")
             loc_city = st.text_input("City (Optional)", key="loc_city")
             loc_street_address = st.text_input("Street Address (Optional)", key="loc_street")
             loc_postal_code = st.text_input("Postal Code (Optional)", key="loc_postal")
             loc_latitude = st.number_input("Latitude (Optional)", value=None, format="%.6f", key="loc_lat")
             loc_longitude = st.number_input("Longitude (Optional)", value=None, format="%.6f", key="loc_lon")
             loc_precision = st.number_input("Precision (meters) (Optional)", value=None, min_value=0.0, format="%.1f", key="loc_prec")
        elif obj_type == 'malware':
             st.subheader("Malware Properties")
             mal_malware_types = st.multiselect("Malware Types (Optional)", options=MALWARE_TYPES_OV[1:], key="mal_types")
             mal_is_family = st.checkbox("Is Family? (Represents a family if checked)", key="mal_is_family")
             mal_aliases_str = st.text_area("Aliases (Optional, one per line)", key="mal_aliases")
             mal_kill_chain_phases_str = st.text_area("Kill Chain Phases (Optional, e.g., kill_chain_name:phase_name\\n...)", key="mal_kill_chain")
             mal_first_seen_str = st.text_input("First Seen (Optional, YYYY-MM-DDTHH:mm:ss.sssZ)", key="mal_first_seen")
             mal_last_seen_str = st.text_input("Last Seen (Optional, YYYY-MM-DDTHH:mm:ss.sssZ)", key="mal_last_seen")
             mal_os_execution_envs_str = st.text_area("OS Execution Envs (Optional, one per line)", key="mal_os")
             mal_architecture_execution_envs_str = st.text_area("Architecture Execution Envs (Optional, e.g., x86, arm)", key="mal_arch")
             mal_implementation_languages_str = st.text_area("Implementation Languages (Optional, e.g., c++, python)", key="mal_langs")
             mal_capabilities_str = st.text_area("Capabilities (Optional, e.g., steals-passwords)", key="mal_caps") # Needs malware-capabilities-ov
             mal_sample_refs_str = st.text_area("Sample Refs (Optional, STIX IDs one per line)", key="mal_samples")
        elif obj_type == 'note':
             st.subheader("Note Properties")
             note_content = st.text_area("Content (Required)")
             note_authors_str = st.text_area("Authors (Optional, one per line)", key="note_authors")
             note_object_refs_str = st.text_area("Object Refs (Required, STIX IDs one per line)", key="note_obj_refs")
        elif obj_type == 'observed-data':
            st.subheader("Observed Data Properties")
            obs_first_observed_str = st.text_input("First Observed (Required, YYYY-MM-DDTHH:mm:ss.sssZ)", key="obs_first")
            obs_last_observed_str = st.text_input("Last Observed (Required, YYYY-MM-DDTHH:mm:ss.sssZ)", key="obs_last")
            obs_number_observed = st.number_input("Number Observed (Required)", min_value=1, value=1, key="obs_num")
            obs_object_refs_str = st.text_area("Object Refs (Required, STIX IDs one per line)", key="obs_obj_refs", help="IDs of SCOs or SROs observed")
        elif obj_type == 'report':
             st.subheader("Report Properties")
             rep_report_types = st.multiselect("Report Types (Required)", options=REPORT_TYPES_OV[1:], key="rep_types")
             rep_published_str = st.text_input("Published Date (Required, YYYY-MM-DDTHH:mm:ss.sssZ)", key="rep_published")
             rep_object_refs_str = st.text_area("Object Refs (Required, STIX IDs one per line)", key="rep_obj_refs")
        elif obj_type == 'threat-actor':
            st.subheader("Threat Actor Properties")
            ta_threat_actor_types = st.multiselect("Threat Actor Types (Required)", options=THREAT_ACTOR_TYPES_OV[1:], key="ta_types")
            ta_aliases_str = st.text_area("Aliases (Optional, one per line)", key="ta_aliases")
            ta_first_seen_str = st.text_input("First Seen (Optional, YYYY-MM-DDTHH:mm:ss.sssZ)", key="ta_first_seen")
            ta_last_seen_str = st.text_input("Last Seen (Optional, YYYY-MM-DDTHH:mm:ss.sssZ)", key="ta_last_seen")
            ta_roles = st.multiselect("Roles (Optional)", options=THREAT_ACTOR_ROLES_OV[1:], key="ta_roles")
            ta_goals_str = st.text_area("Goals (Optional, one per line)", key="ta_goals")
            ta_sophistication = st.selectbox("Sophistication (Optional)", options=THREAT_ACTOR_SOPHISTICATION_OV, key="ta_sophistication")
            ta_resource_level = st.selectbox("Resource Level (Optional)", options=ATTACK_RESOURCE_LEVEL_OV, key="ta_resource_level")
            ta_primary_motivation = st.selectbox("Primary Motivation (Optional)", options=ATTACK_MOTIVATION_OV, key="ta_primary_motivation")
            ta_secondary_motivations = st.multiselect("Secondary Motivations (Optional)", options=ATTACK_MOTIVATION_OV, key="ta_secondary_motivations")
            ta_personal_motivations = st.multiselect("Personal Motivations (Optional)", options=ATTACK_MOTIVATION_OV, key="ta_personal_motivations")
        elif obj_type == 'tool':
             st.subheader("Tool Properties")
             t_tool_types = st.multiselect("Tool Types (Optional)", options=TOOL_TYPES_OV[1:], key="t_types")
             t_aliases_str = st.text_area("Aliases (Optional, one per line)", key="t_aliases")
             t_kill_chain_phases_str = st.text_area("Kill Chain Phases (Optional, e.g., kill_chain_name:phase_name\\n...)", key="t_kill_chain")
             t_tool_version = st.text_input("Tool Version (Optional)", key="t_version")
        elif obj_type == 'vulnerability':
             st.subheader("Vulnerability Properties")
             vuln_cvssv2_score = st.number_input("CVSSv2 Score (Optional)", value=None, min_value=0.0, max_value=10.0, format="%.1f", key="vuln_cvss2")
             vuln_cvssv3_score = st.number_input("CVSSv3 Score (Optional)", value=None, min_value=0.0, max_value=10.0, format="%.1f", key="vuln_cvss3")


        # --- External Reference Fields ---
        st.subheader("External Reference (Optional)")
        ext_ref_source_name = st.text_input("Source Name (Required if adding ref)", key="ext_ref_source")
        ext_ref_description = st.text_input("Description", key="ext_ref_desc")
        ext_ref_url = st.text_input("URL", key="ext_ref_url")
        ext_ref_external_id = st.text_input("External ID", key="ext_ref_ext_id")
        ext_ref_hashes_str = st.text_area("Hashes (Optional, e.g., SHA-256: abc...\\nMD5: def...)", key="ext_ref_hashes")


        # --- Submit Button ---
        add_obj_submit = st.form_submit_button("Create Object")

        if add_obj_submit:
            # --- Validation ---
            validation_passed = True
            error_messages = []
            current_obj_type = st.session_state.add_form_selected_type # Use type from state

            # Required field checks (Use current_obj_type)
            if name_required and not name: error_messages.append(f"Name is required for {current_obj_type}.")
            if current_obj_type == 'threat-actor' and not ta_threat_actor_types: error_messages.append("Threat Actor Types is required for Threat Actor.")
            if current_obj_type == 'indicator' and not ind_pattern_type: error_messages.append("Pattern Type is required for Indicator.")
            if current_obj_type == 'indicator' and not ind_pattern: error_messages.append("Pattern is required for Indicator.")
            if current_obj_type == 'indicator' and not ind_valid_from_str: error_messages.append("Valid From is required for Indicator.")
            if current_obj_type == 'note' and not note_content: error_messages.append("Content is required for Note.")
            if current_obj_type == 'note' and not note_object_refs_str: error_messages.append("Object Refs is required for Note.")
            if current_obj_type == 'observed-data' and not obs_first_observed_str: error_messages.append("First Observed is required for Observed Data.")
            if current_obj_type == 'observed-data' and not obs_last_observed_str: error_messages.append("Last Observed is required for Observed Data.")
            if current_obj_type == 'observed-data' and not obs_object_refs_str: error_messages.append("Object Refs is required for Observed Data.")
            if current_obj_type == 'report' and not rep_report_types: error_messages.append("Report Types is required for Report.")
            if current_obj_type == 'report' and not rep_published_str: error_messages.append("Published Date is required for Report.")
            if current_obj_type == 'report' and not rep_object_refs_str: error_messages.append("Object Refs is required for Report.")

            # External Reference Validation
            ext_ref_provided = ext_ref_description or ext_ref_url or ext_ref_external_id or ext_ref_hashes_str
            if ext_ref_provided and not ext_ref_source_name: error_messages.append("Source Name is required if adding an External Reference.")
            if ext_ref_source_name and not (ext_ref_description or ext_ref_url or ext_ref_external_id): error_messages.append("External Reference requires at least one of Description, URL, or External ID.")

            if error_messages: # Check if any errors were added
                 validation_passed = False
                 for msg in error_messages: st.error(msg)

            # --- Object Creation ---
            if validation_passed:
                obj_id = f"{current_obj_type}--{uuid.uuid4()}"
                obj = { 'type': current_obj_type, 'id': obj_id, 'spec_version': '2.1' }

                # Add common fields
                if name: obj['name'] = name
                if description: obj['description'] = description

                # --- Add type-specific fields ---
                def parse_text_area(text_area_str): return [item.strip() for item in text_area_str.splitlines() if item.strip()]
                def parse_kill_chain(text_area_str):
                    phases = []
                    for line in text_area_str.splitlines():
                         if ':' in line:
                              parts = line.split(':', 1)
                              phases.append({'kill_chain_name': parts[0].strip(), 'phase_name': parts[1].strip()})
                    return phases if phases else None

                # Populate obj dictionary based on current_obj_type
                if current_obj_type == 'attack-pattern':
                     if ap_aliases_str: obj['aliases'] = parse_text_area(ap_aliases_str)
                     kcp = parse_kill_chain(ap_kill_chain_phases_str); obj.update({'kill_chain_phases': kcp} if kcp else {})
                elif current_obj_type == 'campaign':
                     if c_aliases_str: obj['aliases'] = parse_text_area(c_aliases_str)
                     if c_first_seen_str: obj['first_seen'] = c_first_seen_str
                     if c_last_seen_str: obj['last_seen'] = c_last_seen_str
                     if c_objective: obj['objective'] = c_objective
                elif current_obj_type == 'identity':
                     if id_identity_class: obj['identity_class'] = id_identity_class
                     if id_sectors: obj['sectors'] = id_sectors
                     if id_contact_information: obj['contact_information'] = id_contact_information
                elif current_obj_type == 'indicator':
                     if ind_indicator_types: obj['indicator_types'] = ind_indicator_types
                     obj['pattern_type'] = ind_pattern_type
                     obj['pattern'] = ind_pattern
                     obj['valid_from'] = ind_valid_from_str
                     if ind_valid_until_str: obj['valid_until'] = ind_valid_until_str
                     kcp = parse_kill_chain(ind_kill_chain_phases_str); obj.update({'kill_chain_phases': kcp} if kcp else {})
                elif current_obj_type == 'infrastructure':
                     if inf_infrastructure_types: obj['infrastructure_types'] = inf_infrastructure_types
                     if inf_aliases_str: obj['aliases'] = parse_text_area(inf_aliases_str)
                     kcp = parse_kill_chain(inf_kill_chain_phases_str); obj.update({'kill_chain_phases': kcp} if kcp else {})
                     if inf_first_seen_str: obj['first_seen'] = inf_first_seen_str
                     if inf_last_seen_str: obj['last_seen'] = inf_last_seen_str
                elif current_obj_type == 'intrusion-set':
                    if is_aliases_str: obj['aliases'] = parse_text_area(is_aliases_str)
                    if is_first_seen_str: obj['first_seen'] = is_first_seen_str
                    if is_last_seen_str: obj['last_seen'] = is_last_seen_str
                    if is_goals_str: obj['goals'] = parse_text_area(is_goals_str)
                    if is_resource_level: obj['resource_level'] = is_resource_level
                    if is_primary_motivation: obj['primary_motivation'] = is_primary_motivation
                    if is_secondary_motivations: obj['secondary_motivations'] = is_secondary_motivations
                elif current_obj_type == 'location':
                     if loc_region: obj['region'] = loc_region
                     if loc_country: obj['country'] = loc_country
                     if loc_administrative_area: obj['administrative_area'] = loc_administrative_area
                     if loc_city: obj['city'] = loc_city
                     if loc_street_address: obj['street_address'] = loc_street_address
                     if loc_postal_code: obj['postal_code'] = loc_postal_code
                     if loc_latitude is not None: obj['latitude'] = loc_latitude
                     if loc_longitude is not None: obj['longitude'] = loc_longitude
                     if loc_precision is not None: obj['precision'] = loc_precision
                elif current_obj_type == 'malware':
                     if mal_malware_types: obj['malware_types'] = mal_malware_types
                     obj['is_family'] = mal_is_family
                     if mal_aliases_str: obj['aliases'] = parse_text_area(mal_aliases_str)
                     kcp = parse_kill_chain(mal_kill_chain_phases_str); obj.update({'kill_chain_phases': kcp} if kcp else {})
                     if mal_first_seen_str: obj['first_seen'] = mal_first_seen_str
                     if mal_last_seen_str: obj['last_seen'] = mal_last_seen_str
                     if mal_os_execution_envs_str: obj['os_execution_envs'] = parse_text_area(mal_os_execution_envs_str)
                     if mal_architecture_execution_envs_str: obj['architecture_execution_envs'] = parse_text_area(mal_architecture_execution_envs_str)
                     if mal_implementation_languages_str: obj['implementation_languages'] = parse_text_area(mal_implementation_languages_str)
                     if mal_capabilities_str: obj['capabilities'] = parse_text_area(mal_capabilities_str)
                     if mal_sample_refs_str: obj['sample_refs'] = parse_text_area(mal_sample_refs_str)
                elif current_obj_type == 'note':
                     obj['content'] = note_content
                     if note_authors_str: obj['authors'] = parse_text_area(note_authors_str)
                     obj['object_refs'] = parse_text_area(note_object_refs_str)
                elif current_obj_type == 'observed-data':
                     obj['first_observed'] = obs_first_observed_str
                     obj['last_observed'] = obs_last_observed_str
                     obj['number_observed'] = obs_number_observed
                     obj['object_refs'] = parse_text_area(obs_object_refs_str)
                elif current_obj_type == 'report':
                     obj['report_types'] = rep_report_types
                     obj['published'] = rep_published_str
                     obj['object_refs'] = parse_text_area(rep_object_refs_str)
                elif current_obj_type == 'threat-actor':
                    obj['threat_actor_types'] = ta_threat_actor_types
                    if ta_aliases_str: obj['aliases'] = parse_text_area(ta_aliases_str)
                    if ta_first_seen_str: obj['first_seen'] = ta_first_seen_str
                    if ta_last_seen_str: obj['last_seen'] = ta_last_seen_str
                    if ta_roles: obj['roles'] = ta_roles
                    if ta_goals_str: obj['goals'] = parse_text_area(ta_goals_str)
                    if ta_sophistication: obj['sophistication'] = ta_sophistication
                    if ta_resource_level: obj['resource_level'] = ta_resource_level
                    if ta_primary_motivation: obj['primary_motivation'] = ta_primary_motivation
                    if ta_secondary_motivations: obj['secondary_motivations'] = ta_secondary_motivations
                    if ta_personal_motivations: obj['personal_motivations'] = ta_personal_motivations
                elif current_obj_type == 'tool':
                     if t_tool_types: obj['tool_types'] = t_tool_types
                     if t_aliases_str: obj['aliases'] = parse_text_area(t_aliases_str)
                     kcp = parse_kill_chain(t_kill_chain_phases_str); obj.update({'kill_chain_phases': kcp} if kcp else {})
                     if t_tool_version: obj['tool_version'] = t_tool_version
                elif current_obj_type == 'vulnerability':
                     if vuln_cvssv2_score is not None: obj['cvssV2_score'] = vuln_cvssv2_score
                     if vuln_cvssv3_score is not None: obj['cvssV3_score'] = vuln_cvssv3_score

                # Add External Reference
                if ext_ref_source_name and (ext_ref_description or ext_ref_url or ext_ref_external_id):
                    ext_ref = {"source_name": ext_ref_source_name}
                    if ext_ref_description: ext_ref["description"] = ext_ref_description
                    if ext_ref_url: ext_ref["url"] = ext_ref_url
                    if ext_ref_external_id: ext_ref["external_id"] = ext_ref_external_id
                    if ext_ref_hashes_str:
                        hashes_dict = {}
                        for line in ext_ref_hashes_str.splitlines():
                            if ':' in line:
                                parts = line.split(':', 1)
                                algo = parts[0].strip().upper()
                                hash_val = parts[1].strip()
                                if algo in HASH_ALGO_OV and algo != "": hashes_dict[algo] = hash_val
                                else: st.warning(f"Ignoring invalid hash algorithm: {algo}")
                        if hashes_dict: ext_ref["hashes"] = hashes_dict
                    obj["external_references"] = [ext_ref]

                st.session_state.objects.append(obj)
                st.session_state.nodes.append({'data': { 'id': obj_id, 'label': name or obj_id }})
                st.success(f"Created {current_obj_type}")

                # Reset dropdown defaults after adding
                if len(st.session_state.nodes) >= 1: st.session_state.rel_source_sel = st.session_state.nodes[0]['data']['id']
                if len(st.session_state.nodes) >= 2: st.session_state.rel_target_sel = st.session_state.nodes[1]['data']['id']
                else: st.session_state.rel_target_sel = None

                st.rerun()

    # --- Create Relationship (Dropdown Based - Revised Structure) ---
    # (Code remains the same as previous step)
    st.header("Create Relationship")
    eligible_nodes = [o for o in st.session_state.objects if o.get('type') != 'relationship']
    node_options = {o['id']: f"{o.get('name', o.get('value', o.get('id', 'ID Missing')))} ({o.get('type', 'Type Missing')})" for o in eligible_nodes}
    if not eligible_nodes or len(eligible_nodes) < 2:
        st.info("Add at least two non-relationship objects to create a relationship.")
    else:
        default_source_index = 0
        if st.session_state.get('rel_source_sel') in node_options: default_source_index = list(node_options.keys()).index(st.session_state.rel_source_sel)
        default_target_index = 1 if len(node_options) > 1 else 0
        if st.session_state.get('rel_target_sel') in node_options: default_target_index = list(node_options.keys()).index(st.session_state.rel_target_sel)
        if default_target_index >= len(node_options): default_target_index = 0
        def update_rel_sel(source_key, target_key):
            st.session_state.rel_source_sel = st.session_state[source_key]
            st.session_state.rel_target_sel = st.session_state[target_key]
        selected_source_id = st.selectbox("Source Object", options=list(node_options.keys()), format_func=node_options.get, key="rel_source_select_widget", index=default_source_index, on_change=update_rel_sel, args=("rel_source_select_widget", "rel_target_select_widget"))
        selected_target_id = st.selectbox("Target Object", options=list(node_options.keys()), format_func=node_options.get, key="rel_target_select_widget", index=default_target_index, on_change=update_rel_sel, args=("rel_source_select_widget", "rel_target_select_widget"))
        valid_rel_types_for_pair = []
        rel_type_select_disabled = True
        message = ""
        current_source_id = st.session_state.get('rel_source_sel', selected_source_id)
        current_target_id = st.session_state.get('rel_target_sel', selected_target_id)
        if current_source_id and current_target_id:
            if current_source_id == current_target_id: message = "Source and Target cannot be the same."
            else:
                source_type = get_object_type_from_id(current_source_id)
                target_type = get_object_type_from_id(current_target_id)
                if source_type and target_type:
                    key = (source_type, target_type)
                    valid_rel_types_for_pair = HARDCODED_VALID_RELATIONSHIPS.get(key, [])
                    if valid_rel_types_for_pair: rel_type_select_disabled = False
                    else: message = f"No valid relationship types defined for {source_type} -> {target_type}."
                else: message = "Could not determine object types."
        if message and rel_type_select_disabled and current_source_id != current_target_id: st.warning(message)
        with st.form("create_relationship_submit_form"):
            selected_rel_type = st.selectbox("Relationship Type", options=valid_rel_types_for_pair, disabled=rel_type_select_disabled, key="rel_type_select_in_form", index=0 if valid_rel_types_for_pair else None)
            rel_description = st.text_area("Relationship Description (Optional)", key="rel_desc_input_in_form")
            create_rel_button = st.form_submit_button("Create Relationship", disabled=rel_type_select_disabled)
            if create_rel_button:
                if current_source_id and current_target_id and current_source_id != current_target_id and selected_rel_type:
                    rel_id = f"relationship--{uuid.uuid4()}"
                    rel = {'type': 'relationship', 'id': rel_id, 'spec_version': '2.1', 'relationship_type': selected_rel_type, 'source_ref': current_source_id, 'target_ref': current_target_id}
                    if rel_description: rel['description'] = rel_description
                    st.session_state.objects.append(rel)
                    st.session_state.edges.append({'data': {'id': rel_id, 'source': current_source_id, 'target': current_target_id, 'label': selected_rel_type}})
                    st.success(f"Created relationship '{selected_rel_type}'")
                    st.rerun()
                else:
                     if not selected_rel_type: st.error("Cannot create relationship: No valid relationship type selected or available.")
                     elif current_source_id == current_target_id: st.error("Cannot create relationship: Source and Target are the same.")
                     else: st.error("Cannot create relationship. Ensure valid source, target, and type are selected.")

    # --- Remove Selected Element ---
    # (Code remains the same as previous step)
    st.header("Remove Element")
    elements_to_remove_ids = []
    if st.session_state.current_selection and isinstance(st.session_state.current_selection, dict):
        selected_nodes_data = st.session_state.current_selection.get("nodes", [])
        selected_edges_data = st.session_state.current_selection.get("edges", [])
        if selected_nodes_data:
            if selected_nodes_data and isinstance(selected_nodes_data[0], dict): elements_to_remove_ids.extend([node['id'] for node in selected_nodes_data])
            else: elements_to_remove_ids.extend(selected_nodes_data)
        if selected_edges_data:
            if selected_edges_data and isinstance(selected_edges_data[0], dict): elements_to_remove_ids.extend([edge['id'] for edge in selected_edges_data])
            else: elements_to_remove_ids.extend(selected_edges_data)
    if elements_to_remove_ids:
        st.subheader("Selected for Removal:")
        for elem_id in elements_to_remove_ids:
             obj = next((o for o in st.session_state.objects if o.get('id') == elem_id), None)
             label = elem_id
             if obj: label = f"{obj.get('type', 'N/A')}: {obj.get('name', obj.get('value', elem_id))}"
             st.markdown(f"<div class='selected-node'><span class='selected-node-label'>Selected:</span>{label}</div>", unsafe_allow_html=True)
        if st.button("Confirm Removal", key="remove_button"):
            num_removed = len(elements_to_remove_ids)
            for elem_id in elements_to_remove_ids: remove_element(elem_id)
            st.success(f"Removed {num_removed} element(s).")
            st.session_state.current_selection = None
            st.rerun()
    else: st.info("Click an element in the graph to select it for removal.")


# --- GRAPH RENDERING ---
# (Code remains the same as previous step)
st.subheader("Graph View")
valid_nodes = [n for n in st.session_state.nodes if isinstance(n, dict) and 'data' in n and 'id' in n['data']]
valid_edges = [e for e in st.session_state.edges if isinstance(e, dict) and 'data' in e and 'id' in e['data'] and 'source' in e['data'] and 'target' in e['data']]
elements = valid_nodes + valid_edges
stylesheet = [
    { 'selector': 'node', 'style': { 'label': 'data(label)', 'width': 60, 'height': 60, 'background-fit': 'contain', 'background-color': '#ddd', 'border-width': 1, 'border-color': '#555', 'font-size': '9px', 'text-valign': 'bottom', 'text-halign': 'center', 'text-margin-y': 5, 'text-wrap': 'wrap', 'text-max-width': 80, 'color': '#000'}},
    { 'selector': 'edge', 'style': { 'label': 'data(label)', 'width': 2, 'line-color': '#67a3e0', 'target-arrow-color': '#67a3e0', 'target-arrow-shape': 'triangle', 'curve-style': 'bezier', 'font-size': '9px', 'color': '#333', 'text-rotation': 'autorotate', 'text-background-color': '#ffffff', 'text-background-opacity': 0.7, 'text-background-padding': '2px'}},
    { 'selector': ':selected', 'style': { 'border-width': 4, 'border-color': '#e74c3c', 'line-color': '#e74c3c', 'target-arrow-color': '#e74c3c', 'background-color': '#f7cac9', 'z-index': 9999 }}
]
types_in_graph = set(get_object_type_from_id(n['data']['id']) for n in valid_nodes)
for t in types_in_graph:
    if t:
        data_uri = get_icon_data_uri(t)
        if data_uri:
            stylesheet.append({'selector': f'node[id ^= "{t}--"]', 'style': { 'background-image': data_uri, 'background-fit': 'contain', 'background-color': '#fff', 'background-opacity': 0 }})

selected = cytoscape(
    elements=elements, stylesheet=stylesheet,
    layout={ 'name': 'cose', 'idealEdgeLength': 150, 'nodeOverlap': 20, 'padding': 30, 'animate': False },
    width="100%", height="800px", selection_type='multiple',
    key="stix_graph_step8_form_fix" # New key
)

# --- Process Selection FOR REMOVAL ONLY ---
# (Code remains the same as previous step)
current_selection_in_state = st.session_state.get('current_selection')
if selected != current_selection_in_state:
    st.session_state.current_selection = selected
    if (selected and (selected.get('nodes') or selected.get('edges'))) or \
       (not selected and current_selection_in_state is not None):
        st.rerun()


# --- Export STIX bundle ---
# (Code remains the same as previous step)
st.header("Export")
if st.button("Export STIX 2.1 Bundle"):
    if not st.session_state.objects: st.warning("No objects to export.")
    else:
        try:
            bundle_objects = []
            for obj in st.session_state.objects:
                 obj_copy = obj.copy()
                 if 'spec_version' not in obj_copy: obj_copy['spec_version'] = '2.1'
                 bundle_objects.append(obj_copy)
            bundle = Bundle(objects=bundle_objects, allow_custom=True)
            output = bundle.serialize(pretty=True)
            st.download_button(label="Download Bundle JSON", data=output, file_name="stix_bundle.json", mime="application/json")
            st.success("Bundle ready for download.")
        except Exception as e: st.error(f"Error exporting bundle: {e}")

# --- Display Raw Objects ---
# (Code remains the same as previous step)
with st.expander("Show Raw STIX Objects in Session State"):
     if st.session_state.objects: st.json(st.session_state.objects)
     else: st.info("No objects currently in session state.")

