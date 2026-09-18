# Quick Detail / Quick Response Product Contract

Status: **APPROVED REQUIREMENT / IMPLEMENTATION REQUIRED**

## Objective

The Investigate workspace must provide a high-value analyst response immediately after a result is selected, without requiring the user to open the full Record & Provenance page.

For Windows Security Event IDs, Quick Detail is driven by the approved Ultimate Windows Security source policy.

For Sysmon Event IDs, Quick Detail is driven by the approved Microsoft Sysinternals / Microsoft Learn Sysmon source policy.

## Windows Security Quick Detail

When the selected result is a Windows Security Event ID, Quick Detail should present, where the source contains the data:

1. **Identity**
   - Event ID;
   - event title;
   - event type (success/failure/information where applicable);
   - category/subcategory;
   - supported/observed Windows generations;
   - legacy/corresponding Event IDs.

2. **Purpose**
   - concise independently-authored description based on the primary reference.

3. **Field Groups**
   - grouped exactly around the event's logical sections, for example:
     - Subject;
     - Logon Information;
     - New Logon;
     - Process Information;
     - Network Information;
     - Detailed Authentication Information;
     - Creator Subject;
     - Target Subject;
     - other event-specific sections.

4. **Important Fields**
   - native field name;
   - concise meaning;
   - version applicability;
   - enumerated values where applicable;
   - correlation hint where applicable.

5. **Version Notes**
   - fields introduced/changed by later Windows generations;
   - no assumption that every field exists on every version.

6. **Correlations**
   - related Event IDs;
   - correlation key such as Logon ID, Process ID, GUID or another event-specific value;
   - limitations.

7. **Source**
   - visible primary source name;
   - source URL;
   - retrieval/validation status.

## Example target behavior — Event 4624

A search for `4624` should show a selected Quick Detail containing the factual structure represented by the primary reference, including:

- successful-logon identity;
- Logon/Logoff → Logon classification;
- supported Windows generations;
- legacy 528/540 correlation context;
- Subject;
- Logon Information;
- Logon Type value dictionary;
- Impersonation Level;
- New Logon;
- Process Information;
- Network Information;
- Detailed Authentication Information;
- related logoff/authentication correlations;
- version-specific fields such as Restricted Admin Mode, Virtual Account, Elevated Token, Linked Logon ID and newer Remote Credential Guard where applicable.

The implementation must independently phrase explanatory text rather than copying substantial source prose.

## Example target behavior — Event 4688

A search for `4688` should expose:

- process-creation identity/classification;
- legacy 592 relationship;
- Creator Subject;
- Target Subject where applicable;
- New Process ID / Name;
- Token Elevation Type values;
- Mandatory Label integrity values;
- Creator Process ID / Name;
- Process Command Line;
- 4624/4689/process-parent correlation pivots;
- version applicability;
- collection-policy note for command-line capture.

## Density

Quick Detail is allowed to be vertically scrollable. "Quick" means **immediate context**, not "only four fields."

The full Record & Provenance page remains the deeper evidence-oriented experience.

## Fail-closed behavior

If a field/section is not present in the accepted source snapshot:

- do not invent it;
- do not fill it from a different source without explicit source labeling;
- show unavailable/N/A/version-excluded state where useful.

If Quick Detail provenance is missing or invalid, the record may still be searchable, but the Quick Detail must display an evidence-status warning rather than presenting unsourced semantics as verified.
