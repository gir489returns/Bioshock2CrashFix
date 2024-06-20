This mod utilizes SpecialK for several things, mostly to enforce the render thread stacks in lockstep with the main thread, 
but it will also produce accurate crash logs if you wish to have me investigate your specific crash.
Simply extract the contents of the archive into steamapps\common\BioShock 2 Remastered\Build\Final and the instillation should be complete.

The optional build will create a crash.log file inside the PlugIns\ThirdParty\Bioshock2CrashFix folder and write to it every time it catches a crash,
so you can have empirical evidence this is working. There is no runtime cost associated with it, the logger runs in its own thread.

If you do not wish to use SpecialK, simply grab the Bioshock2CrashFix.dll from the PlugIns\ThirdParty\Bioshock2CrashFix folder, 
and rename it dxgi.dll and place it into your steamapps\common\BioShock 2 Remastered\Build\Final folder. The optional file cannot be used this way.
