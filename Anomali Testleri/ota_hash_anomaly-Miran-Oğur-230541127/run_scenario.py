import sys
from pathlib import Path

if __name__ == '__main__':
    # Ensure repo root is in sys.path (two levels up from this file)
    repo_root = Path(__file__).resolve().parents[1]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))

    if len(sys.argv) < 2:
        print('Usage: python run_scenario.py <path-to-scenario-py> [args]')
        sys.exit(1)

    scenario_path = Path(sys.argv[1]).resolve()
    if not scenario_path.exists():
        print(f'Scenario not found: {scenario_path}')
        sys.exit(1)

    # Run the scenario module as a script
    sys.argv = [str(scenario_path)] + sys.argv[2:]
    with open(scenario_path, 'rb') as f:
        code = compile(f.read(), str(scenario_path), 'exec')
        exec(code, {'__name__': '__main__'})
