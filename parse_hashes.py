import json
from datetime import datetime, timezone

# Read API response
with open('response.json') as f:
    raw = f.read()

print(f'Raw API response (first 500 chars): {raw[:500]}')

data = json.loads(raw)
print(f'Keys in response: {list(data.keys())}')

# Write everything in one go
with open('malware-blocklist.txt', 'w') as out:
    out.write('# ============================================\n')
    out.write('# FortiGate External Malware Block List\n')
    out.write('# Source: abuse.ch MalwareBazaar\n')
    out.write('# Maintained by: Harpreet2323\n')
    out.write(f'# Updated: {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}\n')
    out.write('# ============================================\n')
    out.write('\n')

    count = 0

    # Handle different possible response structures
    items = []
    if isinstance(data, list):
        items = data
        print('Response is a LIST')
    elif isinstance(data, dict):
        print(f'Response is a DICT with keys: {list(data.keys())}')
        items = data.get('data', 
               data.get('results',
               data.get('hashes',
               data.get('items', []))))

    for item in items:
        if isinstance(item, dict):
            h = item.get('md5_hash',
                item.get('md5',
                item.get('hash', ''))).strip()
        elif isinstance(item, str):
            h = item.strip()
        else:
            continue

        if len(h) == 32 and all(c in '0123456789abcdefABCDEF' for c in h):
            out.write(h + '\n')
            count += 1

    print(f'Successfully written {count} hashes')
