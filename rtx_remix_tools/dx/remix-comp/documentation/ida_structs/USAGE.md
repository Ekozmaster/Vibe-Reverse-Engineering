1. Open your ida database 
2. Menubar -> View -> Open Subviews -> Local types  
   ![](img/01.jpg)

3. Right click the type window and select Add type (or press Insert)  
![](img/02.jpg)

4. Open one of the two header files, copy all of the content and paste it into the `C syntax` window in ida
5. Repeat for the second header file

6. If you've found a global d3d9 device variable / local var, select it and press `Y`  
![](img/03.jpg)

7. Change the variable type to `IDirect3DDevice9* d3ddev`  
![](img/04.jpg)

8. Result:  
![](img/05.jpg)

____

The same can be done for the d3d9 interface: `IDirect3D9* d3d9`