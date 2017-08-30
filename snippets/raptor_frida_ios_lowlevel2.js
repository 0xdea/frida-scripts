/*
 * raptor_frida_ios_*.js - Frida script snippets for iOS
 * Copyright (c) 2017 Marco Ivaldi <raptor@0xdeadbeef.info>
 *
 * Frida.re JS script snippets for iOS/ObjC instrumentation.
 * See https://www.frida.re/ and https://codeshare.frida.re/
 * for further information on this powerful tool.
 *
 * "We want to help others achieve interop through reverse
 * engineering" -- @oleavr
 *
 * Many thanks to Maurizio Agazzini <inode@wayreth.eu.org>
 * and Federico Dotta <federico.dotta@mediaservice.net>.
 *
 * Example usage:
 * # frida -U -f com.xxx.yyy -l raptor_frida_ios.js --no-pause
 */

if (ObjC.available) {

	// Low-level intercept and backtrace example 

	Interceptor.attach(Module.findExportByName("libSystem.B.dylib", "open"), {

		onEnter: function(args) {

			// debug only the intended calls
			this.flag = 0;
			var filename = Memory.readCString(ptr(args[0]));

			//if (filename.indexOf("Bundle") == -1 && filename.indexOf("Cache") == -1) // exclusion list
			if (filename.indexOf("my.interesting.file") != -1) // inclusion list
				this.flag = 1;
			
			if (this.flag) {
 				console.log("\nopen called from:\n",
            				Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n"), 
						"\n");
				//console.log(filename); // DEBUG
			}
		}
	});

} else {
 	send("error: Objective-C Runtime is not available!");
}
