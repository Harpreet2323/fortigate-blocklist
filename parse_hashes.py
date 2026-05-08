import json
from datetime import datetime

# Read API response
with open('response.json') as f:
    data = json.load(f)

# Write everything in one go
with open('malware-blocklist.txt', 'w') as out:
    out.write('# ============================================\n')
    out.write('# FortiGate External Malware Block List\n')
    out.write('# Source: abuse.ch MalwareBazaar\n')
    out.write('# Maintained by: Harpreet2323\n')
    out.write(f'# Updated: {datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}\n')
    out.write('# ============================================\n')
    out.write('\n')

    if data.get('query_status') == 'ok':
        count = 0
        for item in data.get('data', []):
            h = item.get('md5_hash', '').strip()
            if len(h) == 32:
                out.write(h + '\n')
                count += 1
        print(f'Successfully written {count} hashes')
    else:
        print(f'API Error: {data.get("query_status")}')
        print(f'Full response: {data}')
