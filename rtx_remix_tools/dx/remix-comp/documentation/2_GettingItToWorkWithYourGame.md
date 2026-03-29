# Getting it to work with your game

If you setup the global path variable named `REMIX_COMP_ROOT` that points to your game folder & `REMIX_COMP_ROOT_EXE` before generating the project files, you are off to a good start. If not, either do that and regenerate the project or manually set the output directory for the .asi so that it ends up in your game/plugins folder. Then set the debug directory to your game dir and the debug command so that it starts your game exe.

I've added comments starting with `#Step` so you can also search the codebase for the most important locations.

- ##### `main.cpp`
```cpp
  	// #Step 1: Start the game and copy the class name from the console window and put it in here:
	#define WINDOW_CLASS_NAME "YOUR_WINDOW_CLASS_NAME" // Eg: "GameFrame"
```

<br>

- ##### `comp.cpp`
I usually create more general hooks in here, such as anti culling code and general setup.

```cpp
  	// #Step 2: init remix api if you want to use it or comment it otherwise
  	// Requires "exposeRemixApi = True" in the "bridge.conf" that is located in the .trex folder
  	shared::common::remix_api::initialize(nullptr, nullptr, nullptr, false);

    // ...

    // #Step 3: hook dinput if your game uses direct input (for ImGui) - ONLY USE ONE
    //shared::common::loader::module_loader::register_module(std::make_unique<shared::common::dinput_v1>()); // v1: might cause issues with the Alt+X menu
    //shared::common::loader::module_loader::register_module(std::make_unique<shared::common::dinput_v2>()); // v2: better but might need further tweaks
```

<br>

- ##### `renderer.cpp`
Look through the code examples in renderer and game.cpp/hpp.
Take a look at the vertex format of drawcalls by uncommenting and breakpointing:

```cpp
    renderer::on_draw_indexed_prim(/* ... */)
    {
        // ..

        // #Step4: uncomment and debug into this to see vertex format of current drawcall
	    // shared::utils::lookat_vertex_decl(dev);
    }
```

If the vertex formats fits fixed function rendering (full precision floats), you are off to a good start.  
You should now look for the mesh transformation matrix so that meshes can be rendered via fixed function (if your game is a shader title) and for ways to differentiate between different types of meshes where you want to make changes to the drawcalls.

More detail on that can be found here: [Identify Drawcalls](3_IdentifyDrawcalls.md)


```cpp
  	renderer::renderer()
    {
	    p_this = this;

	    // #Step 5: Create hooks as required
        // ...
    }
```