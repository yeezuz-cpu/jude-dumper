# Jude offset dumper

A CS2 dumper built for Jude. It finds the offsets and checks the signatures the
project uses; it doesn't try to dump everything in the game.

This is a work in progress. It isn't complete yet, and I'll keep updating it as
I work on Jude.

## Running it

Install Python 3.10 or newer and run these commands from the dumper folder:

```powershell
python -m pip install -r requirements.txt
python dump.py
```

If Steam is installed somewhere else, point `--game` at CS2's `game` folder:

```powershell
python dump.py --game "D:\SteamLibrary\steamapps\common\Counter-Strike Global Offensive\game"
```

The dumper reads the installed DLLs directly. CS2 doesn't need to be running.
It writes `build/offsets/offsets.txt` and a detailed JSON report in the same
folder. The report compares offsets with the previous run when available.
When available, the output includes the installed CS2 patch version from
`game/csgo/steam.inf`.

Use `--write-header` to also regenerate Jude's `src/generated/offsets.h`. It
won't update the rest of the code or build the DLL. Source signature and RTTI
checks depend on Jude's `src` directory; use `--root` to point to it if needed.
Without the Jude source, those checks are skipped.

## Limits

Missing or ambiguous matches are left out of the text dump. A signature match
doesn't prove that a function's arguments, structures, or behavior are unchanged.
The report lists hardcoded addresses for review; it doesn't resolve all of them.
Schema requests are inventoried, but a log timestamp alone doesn't confirm their
values for the current build.
