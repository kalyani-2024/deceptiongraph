#!/usr/bin/env bash
# DeceptionGraph demo, in the order the story makes sense.
#
#   ./scripts/demo.sh               # pauses between sections (for presenting)
#   ./scripts/demo.sh --no-pause    # runs straight through
#   ./scripts/demo.sh --trials 500  # heavier experiment
#
# Run it from the project root with the venv active.

set -e

pause=1
trials=200
while [ $# -gt 0 ]; do
    case "$1" in
        --no-pause) pause=0 ;;
        --trials) trials="$2"; shift ;;
        *) echo "unknown option: $1" >&2; exit 1 ;;
    esac
    shift
done

ref="data/networks/enterprise.yaml"
big="data/networks/campus.yaml"
rule=$(printf '=%.0s' $(seq 1 78))

step() {
    echo
    echo "$rule"
    echo "  $1"
    if [ -n "$2" ]; then echo "  $2"; fi
    echo "$rule"
    echo
}

pause_here() {
    if [ "$pause" -eq 1 ]; then
        echo
        read -r -p "  [enter to continue]" _
    fi
}

if [ ! -f "$ref" ]; then
    echo "Run this from the project root (data/networks/ not found)." >&2
    exit 1
fi

if ! command -v dgraph >/dev/null 2>&1; then
    echo "dgraph not found. Activate the venv first: source .venv/bin/activate" >&2
    exit 1
fi

echo
echo "  DeceptionGraph - adaptive cyber-deception digital twin"
echo "  5-host reference network, then a 16-host campus for the experiments."

# 1 ---------------------------------------------------------------------------
step "1. The digital twin" "A network defined in YAML becomes a graph of assets."
dgraph discover "$ref"
pause_here

# 2 ---------------------------------------------------------------------------
step "2. How an attacker gets in" "The attack graph, and the single most dangerous route."
dgraph paths "$ref"
pause_here

# 3 ---------------------------------------------------------------------------
step "3. What is most at risk" "Reachability x value, kept separate from intrinsic softness."
dgraph risk "$ref"
pause_here

# 4 ---------------------------------------------------------------------------
step "4. Where would they go next?" "If web01 falls, the predicted next move and objective."
dgraph predict "$ref" --from web01
pause_here

# 5 ---------------------------------------------------------------------------
step "5. Where to put the decoys" "Choke points become placements; each decoy imitates a real asset."
dgraph deceive "$ref" --budget 3
pause_here

# 6 ---------------------------------------------------------------------------
step "6. Comparing placement strategies" "By expected coverage, before any simulation."
dgraph compare "$ref" --budget 2
pause_here

# 7 ---------------------------------------------------------------------------
step "7. The adaptation loop" "A simulated intrusion. Watch DECEPTION TRIGGERED and the re-placement."
dgraph simulate "$big" --budget 3 --runs 8 --seed 3
pause_here

# 8 ---------------------------------------------------------------------------
step "8. Does it actually work?" "$trials Monte Carlo intrusions per strategy, paired on the seed."
dgraph experiment "$big" --budget 3 --trials "$trials" --seed 2024
pause_here

# 9 ---------------------------------------------------------------------------
step "9. The agent tool surface" "The same system exposed as MCP-style tools."
python - <<'EOF'
from deceptiongraph.agent import DeceptionGraphTools
t = DeceptionGraphTools('data/networks/enterprise.yaml')
print('tools:', ', '.join(x.name for x in t.tools()))
print('mutating:', ', '.join(x.name for x in t.tools() if x.mutates))
print()
d = t.call('deploy_deception', {'budget': 3})
print('deployed:', ', '.join(x['host_id'] for x in d['decoys']))
print()
r = t.call('report_event', {'type': 'DECOY_AUTHENTICATED', 'actor_id': 'apt-1',
                            'token': d['decoys'][1]['token'],
                            'detail': 'read fake database credentials'})
print(r['narrative'])
EOF
pause_here

# 10 --------------------------------------------------------------------------
step "10. The test suite" "354 tests, no database or container needed."
pytest
pause_here

step "Done" "Optional: 'dgraph serve' for the HTTP API, then open http://127.0.0.1:8000/docs"
echo "  Full JSON report:  dgraph report $ref --out report.json"
echo "  Graph export:      dgraph export $ref --out graph.json"
echo
