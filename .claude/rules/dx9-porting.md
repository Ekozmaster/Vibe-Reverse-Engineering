---
paths:
  - "patches/**/renderer.cpp"
  - "patches/**/ffp_state.cpp"
  - "patches/**/ffp_state.hpp"
  - "patches/**/*.ini"
  - "patches/**/game.cpp"
  - "patches/**/game.hpp"
  - "patches/**/structs.hpp"
---

# DX9 FFP Porting — Active

You are editing per-game remix-comp-proxy files. The `dx9-ffp-port` skill is the authoritative reference — invoke it if not already loaded.

Key constraints for this context:
- `renderer.cpp` draw routing changes must follow the DrawIndexedPrimitive and DrawPrimitive decision trees in the skill
- `ffp_state.hpp` register layout changes require a rebuild (`build.bat release`)
- `remix-comp-proxy.ini` changes take effect on next game launch — no rebuild needed
- Never enable `[Skinning] Enabled=1` without first running `find_skinning.py` on the binary
- After any matrix register change, verify with `livetools trace` before declaring it correct
