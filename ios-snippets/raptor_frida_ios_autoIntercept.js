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

// print arg/ret type
function printType(desc, arg)
{
	try {
		console.log(desc + ObjC.Object(arg).$class + " " + ObjC.Object(arg).$className);
	}
	catch(err) {
		// do nothing
	}
}

// print arg/ret value
function printValue(desc, arg)
{
	try {
		console.log(desc + ObjC.Object(arg));
	}
	catch(err) {
		console.log(desc + arg);
	}
}

// main interceptor
function autoIntercept(target)
{
	var className = target.match(/^[-+]\[(.*)\s/)[1];
	var methodType = target.match(/^([-+])/)[1];	
	var methodName = target.match(/^[-+]\[.*\s(.*)\]/)[1];
	var argCount = (methodName.match(/:/g) || []).length;

	console.log("\ninfo: trying to intercept", target);
	var oldImpl = ObjC.classes[className][methodType + " " + methodName];

	Interceptor.attach(oldImpl.implementation, {

		onEnter: function(args) {

			// debug only the intended calls
			this.flag = 0;
			//if (ObjC.Object(args[2]).toString() == "1234567890abcdef1234567890abcdef12345678")
				this.flag = 1;

			if (this.flag) {

				console.log("\n*** entered", target, "***");

				// print args
				for (i = 0; i < argCount; i++) {
					printType("\narg " + (i + 1) + " type:\t", args[i + 2]);
					printValue("arg " + (i + 1) + " value:\t", args[i + 2]);
				}
			}
		},

		onLeave: function(retval) {

			if (this.flag) {

				// print retval
				printType("\nretval type:\t", retval);
				printValue("retval value:\t", retval);

				console.log("\n*** exiting", target, "***");
			}
		}

	});
}

if (ObjC.available) {

	// autoIntercept("-[CredManager setPassword:]");
	
} else {
 	send("error: Objective-C Runtime is not available!");
}
