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

	// Low-level intercept and binary data print example

	Interceptor.attach(Module.findExportByName("libSystem.B.dylib", "CCCrypt"), {

		onEnter: function(args) {
			console.log("\n*** entered CCCrypt ***");
			console.log("\nkey:");
			console.log(hexdump(ptr(args[3]), {
				offset:	0,
				length:	parseInt(args[4]),
				header:	true,
				ansi:	true
			}));
			console.log("\ndataIn:");
			console.log(hexdump(ptr(args[6]), {
				offset:	0,
				length:	parseInt(args[7]),
				header:	true,
				ansi:	true
			}));
			this.ret = args[8];
			this.retlen = args[9];
		},

		onLeave: function(retval) {
			console.log("\ndataOut:");
			console.log(hexdump(ptr(this.ret), {
				offset:	0,
				length:	parseInt(this.retlen),
				header:	true,
				ansi:	true
			}));
			console.log("\n*** exiting CCCrypt ***");
		}
	});

} else {
 	send("error: Objective-C Runtime is not available!");
}
