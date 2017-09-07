/*
 * raptor_frida_android_*.js - Frida snippets for Android
 * Copyright (c) 2017 Marco Ivaldi <raptor@0xdeadbeef.info>
 *
 * Frida.re JS script snippets for Android instrumentation.
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
 * # frida -U -f com.xxx.yyy -l raptor_frida_android.js --no-pause
 */

setTimeout(function() { // avoid java.lang.ClassNotFoundException

	Java.perform(function() {
		
		// Low-level intercept and backtrace example

		Interceptor.attach(Module.findExportByName("/system/lib/libc.so", "open"), {

			onEnter: function(args) {

				// debug only the intended calls
				this.flag = false;
				// var filename = Memory.readCString(ptr(args[0]));
				// if (filename.indexOf("XYZ") === -1 && filename.indexOf("ZYX") === -1) // exclusion list
				// if (filename.indexOf("my.interesting.file") !== -1) // inclusion list
					this.flag = true;

				if (this.flag) {
					console.warn("\n*** entered open");

					var filename = Memory.readCString(ptr(args[0]));
					console.log("\nfile name: " + filename);

					// print backtrace
					console.log("\nBacktrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE)
							.map(DebugSymbol.fromAddress).join("\n"));
				}
			},

			onLeave: function(retval) {

				if (this.flag) {
					// print retval
					console.log("\nretval: " + retval);
					console.warn("\n*** exiting open");
				}
			}

		});   

	});   

}, 0);
