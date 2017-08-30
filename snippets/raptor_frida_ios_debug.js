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

	// Debug a method

	var oldImpl = ObjC.classes.KeychainManager["+ readKey:"];

	// console.log(ptr(oldImpl.implementation)); // DEBUG

	Interceptor.attach(oldImpl.implementation, {

		onEnter: function(args) {

			// debug only the intended calls
			this.flag = 0;
			//if (ObjC.Object(args[2]).toString() == "1234567890abcdef1234567890abcdef12345678")
				this.flag = 1;
			
			if (this.flag) {
				console.log("info: entered method");

				// 1st arg
				if (args[2]) {
					var obj = ObjC.Object(args[2]);
					console.log("args[2] type:", obj.$class, obj.$className);
					console.log("args[2] value:", obj.toString());
				}

				// 2nd arg
				if (args[3]) {
					var obj = ObjC.Object(args[3]);
					console.log("args[3] type:", obj.$class, obj.$className);
					console.log("args[3] value:", obj.toString());
				}
			}
		},

		onLeave: function(retval) {

			if (this.flag) {
				console.log("info: exiting method");

				// retval
				if (retval) {
					var obj = ObjC.Object(retval);
					console.log("retval type:", obj.$class, obj.$className);
					console.log("retval value:", obj.toString());
				}
			}
		}

	});

} else {
 	send("error: Objective-C Runtime is not available!");
}
