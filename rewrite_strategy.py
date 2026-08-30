import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassStrategy.kt", "r") as f:
    lines = f.readlines()

out_lines = []
for i, line in enumerate(lines):
    if "val status: ImplementationStatus = ImplementationStatus.VALIDATED" in line:
        out_lines.append(line.replace("= ImplementationStatus.VALIDATED", ""))
        continue
        
    # Match enum entries. Usually looks like: ENUM_NAME(param1, param2...),
    # Or ENUM_NAME,
    match = re.match(r'^(\s+)([A-Z0-9_]+)(\((.*?)\))?(,?)$', line)
    if match:
        indent = match.group(1)
        name = match.group(2)
        params_str = match.group(4) if match.group(4) else ""
        comma = match.group(5)
        
        # Determine status
        status = "ImplementationStatus.VALIDATED" # fallback
        if any(x in name for x in ["TCP_ACK", "TCP_URGENT", "TCP_WINDOW", "TCP_SACK", "TCP_TIMESTAMP", "TCP_OVERLAP", "TCP_REORDER", "QUIC_MTU", "UDP_IP_ID", "TCP_FRAGMENT", "TCP_SEGMENT", "TCP_MSS"]):
            status = "ImplementationStatus.UNSUPPORTED"
            
        # Parse params to see if status is already there
        if "ImplementationStatus" in params_str:
            # already has status, keep as is
            # except if it is VALIDATED but should be UNSUPPORTED
            if status == "ImplementationStatus.UNSUPPORTED" and "ImplementationStatus.VALIDATED" in params_str:
                params_str = params_str.replace("ImplementationStatus.VALIDATED", "ImplementationStatus.UNSUPPORTED")
            out_lines.append(f"{indent}{name}({params_str}){comma}\n")
        else:
            # Needs status.
            # We need to fill in missing defaults if we are adding the 5th parameter positionally.
            # Let's count existing parameters
            params = [p.strip() for p in params_str.split(",")] if params_str else []
            if len(params) == 1 and params[0] == "":
                params = []
                
            # defaults: StrategyFamily.GENERIC, 1, 1, StrategyGroup.MEDIUM
            if len(params) == 0:
                params = ["StrategyFamily.GENERIC", "1", "1", "StrategyGroup.MEDIUM"]
            elif len(params) == 1:
                params.extend(["1", "1", "StrategyGroup.MEDIUM"])
            elif len(params) == 2:
                params.extend(["1", "StrategyGroup.MEDIUM"])
            elif len(params) == 3:
                params.append("StrategyGroup.MEDIUM")
                
            params.append(status)
            out_lines.append(f"{indent}{name}({', '.join(params)}){comma}\n")
    else:
        out_lines.append(line)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassStrategy.kt", "w") as f:
    f.writelines(out_lines)

