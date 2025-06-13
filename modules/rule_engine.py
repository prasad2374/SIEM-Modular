# rule_engine.py
import json
import streamlit as st

def load_rules(rule_file, st):
    try:
        rules_json = json.load(rule_file)
        rules = rules_json.get("rules", [])
        chain_rules = rules_json.get("chains", [])
        threshold_overrides = {}

        st.sidebar.subheader("⚙️ Rule Threshold Controls")
        for rule in rules:
            rule_id = rule.get("rule_id", rule["name"])
            threshold = rule.get("threshold", {})
            default_count = threshold.get("count", 5)

            threshold_overrides[rule_id] = st.sidebar.slider(
                f"Threshold Count for '{rule['name']}'",
                min_value=1,
                max_value=100,
                value=default_count,
                step=1
            )

        log_type_guess = rules[0].get("log_type", "Generic") if rules else "Unknown"
        return rules, chain_rules, threshold_overrides, log_type_guess

    except Exception as e:
        st.error(f"Error loading rules: {e}")
        return [], [], {}, "Unknown"

def apply_rules(df_logs, rules, log_type_guess, threshold_overrides, st):
    for rule in rules:
        rule_id = rule.get("rule_id", rule["name"])
        conditions = rule.get("conditions", [])
        threshold_count = threshold_overrides.get(rule_id, rule.get("threshold", {}).get("count", 5))
        matched_indexes = set()

        for condition in conditions:
            field = condition.get("field")
            value = condition.get("value")
            operator = condition.get("operator", "equals")

            if not field or value is None or field not in df_logs.columns:
                st.warning(f"Skipping rule '{rule['name']}': field '{field}' not found.")
                continue

            if operator == "equals":
                matches = df_logs[df_logs[field] == value]
            elif operator == "contains":
                matches = df_logs[df_logs[field].astype(str).str.contains(str(value), case=False, na=False)]
            elif operator == "in":
                matches = df_logs[df_logs[field].isin(value if isinstance(value, list) else [value])]
            else:
                st.warning(f"Unsupported operator '{operator}' in rule '{rule['name']}'")
                continue

            matched_indexes.update(matches.index)

        if len(matched_indexes) >= threshold_count:
            df_logs.loc[list(matched_indexes), "rule_triggered"] = rule["name"]
            st.warning(f"Rule Triggered: {rule['name']} — {len(matched_indexes)} matches")

def detect_chains(df_logs, chain_rules, st):
    for chain in chain_rules:
        sequence = chain.get("sequence", [])
        if all(df_logs["rule_triggered"].astype(str).str.contains(rule).any() for rule in sequence):
            st.error(f"Chain Rule Triggered: {chain['name']}")
