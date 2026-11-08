# DeceptionGraph demo, in the order the story makes sense.
#
#   .\scripts\demo.ps1              # pauses between sections (for presenting)
#   .\scripts\demo.ps1 -NoPause     # runs straight through
#   .\scripts\demo.ps1 -Trials 500  # heavier experiment
#   .\scripts\demo.ps1 -Lanl D:\lanl\prepared500 -LanlModels D:\lanl\models500
#                                   # include the real-data results
#
# Run it from the project root with the venv active.

param(
    [switch]$NoPause,
    [int]$Trials = 200,
    [string]$Lanl = "",
    [string]$LanlModels = "models"
)

$ErrorActionPreference = "Stop"
$ref = "data\networks\enterprise.yaml"
$big = "data\networks\campus.yaml"

function Step {
    param([string]$Title, [string]$Why)
    Write-Host ""
    Write-Host ("=" * 78) -ForegroundColor DarkCyan
    Write-Host "  $Title" -ForegroundColor Cyan
    if ($Why) { Write-Host "  $Why" -ForegroundColor DarkGray }
    Write-Host ("=" * 78) -ForegroundColor DarkCyan
    Write-Host ""
}

function Pause-Here {
    if (-not $NoPause) {
        Write-Host ""
        Write-Host "  [enter to continue]" -ForegroundColor DarkGray -NoNewline
        [void][System.Console]::ReadLine()
    }
}

if (-not (Test-Path $ref)) {
    Write-Host "Run this from the project root (data\networks\ not found)." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "  DeceptionGraph - adaptive cyber-deception digital twin" -ForegroundColor White
Write-Host "  5-host reference network, then a 16-host campus for the experiments." -ForegroundColor DarkGray

# 1 ---------------------------------------------------------------------------
Step "1. The digital twin" "A network defined in YAML becomes a graph of assets."
dgraph discover $ref
Pause-Here

# 2 ---------------------------------------------------------------------------
Step "2. How an attacker gets in" "The attack graph, and the single most dangerous route."
dgraph paths $ref
Pause-Here

# 3 ---------------------------------------------------------------------------
Step "3. What is most at risk" "Reachability x value, kept separate from intrinsic softness."
dgraph risk $ref
Pause-Here

# 4 ---------------------------------------------------------------------------
Step "4. Where would they go next?" "If web01 falls, the predicted next move and objective."
dgraph predict $ref --from web01
Pause-Here

# 5 ---------------------------------------------------------------------------
Step "5. Where to put the decoys" "Choke points become placements; each decoy imitates a real asset."
dgraph deceive $ref --budget 3
Pause-Here

# 6 ---------------------------------------------------------------------------
Step "6. Comparing placement strategies" "By expected coverage, before any simulation."
dgraph compare $ref --budget 2
Pause-Here

# 7 ---------------------------------------------------------------------------
Step "7. The adaptation loop" "A simulated intrusion. Watch DECEPTION TRIGGERED and the re-placement."
dgraph simulate $big --budget 3 --runs 8 --seed 3
Pause-Here

# 8 ---------------------------------------------------------------------------
Step "8. Does it actually work?" "$Trials Monte Carlo intrusions per strategy, paired on the seed."
dgraph experiment $big --budget 3 --trials $Trials --seed 2024
Pause-Here

# 9 ---------------------------------------------------------------------------
Step "9. Against a smarter attacker" "Naive is the upper bound; cautious spots decoys; learning remembers them."
dgraph adversary $big --budget 3 --trials 150 --seed 7
Pause-Here

# 10 --------------------------------------------------------------------------
Step "10. Does it depend on our guesses?" "Vary one judgement-call probability 0.5x-1.5x; does the winner change?"
dgraph sensitivity $big --trials 100 --seed 7 --parameters session_hijack_base,patch_damping
Pause-Here

# 11 --------------------------------------------------------------------------
Step "11. From a real inventory" "An nmap scan plus a zone policy becomes the twin (fictional lab scan)."
$lab = Join-Path $env:TEMP "dgraph-lab.yaml"
dgraph import nmap data\discovery\lab-scan.xml --zones data\discovery\lab-zones.yaml --out $lab
dgraph paths $lab --target db01
Pause-Here

# 12 --------------------------------------------------------------------------
if ($Lanl -and (Test-Path $Lanl)) {
    Step "12. Against the real red team (LANL)" "Every strategy, scored on the held-out half of a real attack."
    dgraph lanl evaluate $Lanl --models $LanlModels --budgets 5,10
    Pause-Here
} else {
    Step "12. Real data (skipped)" "Pass -Lanl <prepared dir> -LanlModels <models dir> to include LANL results."
}

# 13 --------------------------------------------------------------------------
Step "13. The agent tool surface" "The same system exposed as MCP-style tools."
python -c @"
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
"@
Pause-Here

# 14 --------------------------------------------------------------------------
Step "14. The test suite" "455 tests, no database or container needed (integration: scripts\integration.ps1)."
pytest
Pause-Here

Step "Done" "Optional: 'dgraph serve' for the HTTP API, then open http://127.0.0.1:8000/docs"
Write-Host "  Full JSON report:  dgraph report $ref --out report.json" -ForegroundColor DarkGray
Write-Host "  Graph export:      dgraph export $ref --out graph.json" -ForegroundColor DarkGray
Write-Host ""
