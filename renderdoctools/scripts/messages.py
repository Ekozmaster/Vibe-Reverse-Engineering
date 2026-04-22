# renderdoctools/scripts/messages.py
# Retrieve API debug/validation messages from the capture.
# Runs inside RenderDoc Python 3.6. _cfg, _controller, _cap, rd available from base header.

severity_filter = _cfg.get("severity_filter", "all").lower()

# Map severity enum values to readable names
severity_names = {
    rd.MessageSeverity.High: "high",
    rd.MessageSeverity.Medium: "medium",
    rd.MessageSeverity.Low: "low",
    rd.MessageSeverity.Info: "info",
}

# Map category enum values to readable names
category_names = {
    rd.MessageCategory.Application_Defined: "Application_Defined",
    rd.MessageCategory.Miscellaneous: "Miscellaneous",
    rd.MessageCategory.Initialization: "Initialization",
    rd.MessageCategory.Cleanup: "Cleanup",
    rd.MessageCategory.Compilation: "Compilation",
    rd.MessageCategory.State_Creation: "State_Creation",
    rd.MessageCategory.State_Setting: "State_Setting",
    rd.MessageCategory.State_Getting: "State_Getting",
    rd.MessageCategory.Resource_Manipulation: "Resource_Manipulation",
    rd.MessageCategory.Execution: "Execution",
    rd.MessageCategory.Shaders: "Shaders",
    rd.MessageCategory.Deprecated: "Deprecated",
    rd.MessageCategory.Undefined: "Undefined",
    rd.MessageCategory.Portability: "Portability",
    rd.MessageCategory.Performance: "Performance",
}

# Map source enum values to readable names
source_names = {
    rd.MessageSource.API: "API",
    rd.MessageSource.RedundantAPIUse: "RedundantAPIUse",
    rd.MessageSource.IncorrectAPIUse: "IncorrectAPIUse",
    rd.MessageSource.GeneralPerformance: "GeneralPerformance",
    rd.MessageSource.GCNPerformance: "GCNPerformance",
    rd.MessageSource.RuntimeWarning: "RuntimeWarning",
    rd.MessageSource.UnsupportedConfiguration: "UnsupportedConfiguration",
}

# Severity priority for filtering: high is most severe
severity_priority = {"high": 0, "medium": 1, "low": 2, "info": 3}

# Replay to the last event to ensure all messages are generated
actions = _controller.GetRootActions()
if actions:
    last = actions[-1]
    while last.children:
        last = last.children[-1]
    _controller.SetFrameEvent(last.eventId, True)

# Retrieve all debug messages
msgs = _controller.GetDebugMessages()

messages = []
for m in msgs:
    sev = severity_names.get(m.severity, str(m.severity))

    # Apply severity filter
    if severity_filter != "all":
        if severity_filter in severity_priority:
            msg_priority = severity_priority.get(sev, 99)
            filter_priority = severity_priority[severity_filter]
            if msg_priority > filter_priority:
                continue
        elif sev != severity_filter:
            continue

    cat = category_names.get(m.category, str(m.category))
    src = source_names.get(m.source, str(m.source))

    messages.append({
        "eventId": m.eventId,
        "category": cat,
        "severity": sev,
        "source": src,
        "messageID": m.messageID,
        "description": m.description,
    })

# Summary counts by severity
counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
for m in messages:
    sev = m["severity"]
    if sev in counts:
        counts[sev] += 1

_write_output({
    "messages": messages,
    "total": len(messages),
    "counts": counts,
    "severity_filter": severity_filter,
})
_shutdown()
sys.exit(0)
