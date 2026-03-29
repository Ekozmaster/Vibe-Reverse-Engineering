## Solution
Codebase is made to be used with VisualStudio 22 or 26.  
The solution is generated using premake `tools/premake5.exe` - `premake5.lua`.  

#### _shared
- Contains reusable code not specific to a single game such as:
  Hooking, Vector Class, Utility code, Debug Console, DirectInput hook, RemixApi module
- Static lib

### remix-comp-base
- Game specific code
- Full d3d9 proxy interface
- ImGui debug menu
- Logic to ease modification of drawcalls

## Dependencies
Deps are located inside `deps` with premake files for them inside `deps/premake`.  
- `bridge_api` contains the remixApi header files of remix release 1.3.6

<br>

# remix-comp-base

### `src/comp/game`
Meant for game memory offsets, variables, function definitions and structures used by the game.

- ##### `game.cpp :: init_game_addresses()`
  Will be called on init to search for defined patterns, assign memory addresses to variables and function templates.

<br>

### `src/comp/modules`
Contains modules loaded by a module loader (`_shared/common/loader`). These can be registered at will and their load order and point of init defined. Most modules will be loaded within `comp.cpp` after the game window was created. Modules that need to be loaded as soon as possible should be added to `main.cpp` (eg: d3d9ex)

Registration is done like so:  

`shared::common::loader::module_loader::register_module(std::make_unique<imgui>());`

- ##### `d3d9ex`
  Automatically hooks `Direct3DCreate9` and creates a proxy interface.  
  `DrawPrimitive` and `DrawIndexedPrimitive` are redirected to the renderer module.  
  `BeginScene`, `EndScene` also have calls and logic for other modules. 

- #### `imgui`
  Basic ImGui menu that can be opened via F4.  
  Has basic statistics, fake camera options

- #### `renderer`
  Contains per drawcall logic and assembly stubs to uniquely identify certain drawcalls or types of meshes.

  `init_texture_addons()`: can be used to easily load additional textures that can then be used with SetTexture  
  `renderer::on_draw_primitive()`: called on each draw primitive call from the game and can be used to modify a drawcall  `renderer::on_draw_indexed_prim()`: called on each draw indexed primitive call and can be used to modify a drawcall 