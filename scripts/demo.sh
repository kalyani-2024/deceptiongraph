#!/usr/bin/env bash
# DeceptionGraph demo, in the order the story makes sense.
#
#   ./scripts/demo.sh               # pauses between sections (for presenting)
#   ./scripts/demo.sh --no-pause    # runs straight through
#   ./scripts/demo.sh --trials 500  # heavier experiment
#   ./scripts/demo.sh --lanl /data/lanl/prepared500 --lanl-models /data/lanl/models500
#                                   # include the real-data results
#
# Run it from the project root with the venv active.

set -e

pause=1
trials=200
lanl=""
lanl_models="models"
while [ $# -gt 0 ]; do
    case "$1" in
        --no-pause) pause=0 ;;
        --trials) trials="$2"; shift ;;
        --lanl) lanl="$2"; shift ;;
        --lanl-models) lanl_models="$2"; shift ;;
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
step "9. Against a smarter attacker" "Naive is the upper bound; cautious spots decoys; learning remembers them."
dgraph adversary "$big" --budget 3 --trials 150 --seed 7
pause_here

# 10 --------------------------------------------------------------------------
step "10. Does it depend on our guesses?" "Vary one judgement-call probability 0.5x-1.5x; does the winner change?"
dgraph sensitivity "$big" --trials 100 --seed 7 --parameters session_hijack_base,patch_damping
pause_here

# 11 --------------------------------------------------------------------------
step "11. From a real inventory" "An nmap scan plus a zone policy becomes the twin (fictional lab scan)."
lab="${TMPDIR:-/tmp}/dgraph-lab.yaml"
dgraph import nmap data/discovery/lab-scan.xml --zones data/discovery/lab-zones.yaml --out "$lab"
dgraph paths "$lab" --target db01
pause_here

# 12 --------------------------------------------------------------------------
if [ -n "$lanl" ] && [ -d "$lanl" ]; then
    step "12. Against the real red team (LANL)" "Every strategy, scored on the held-out half of a real attack."
    dgraph lanl evaluate "$lanl" --models "$lanl_models" --budgets 5,10
    pause_here
else
    step "12. Real data (skipped)" "Pass --lanl <prepared dir> --lanl-models <models dir> to include LANL results."
fi

# 13 --------------------------------------------------------------------------
step "13. The agent tool surface" "The same system exposed as MCP-style tools."
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

# 14 --------------------------------------------------------------------------
step "14. The test suite" "455 tests, no database or container needed (integration: scripts/integration.sh)."
pytest
pause_here

step "Done" "Optional: 'dgraph serve' for the HTTP API, then open http://127.0.0.1:8000/docs"
echo "  Full JSON report:  dgraph report $ref --out report.json"
echo "  Graph export:      dgraph export $ref --out graph.json"
echo
