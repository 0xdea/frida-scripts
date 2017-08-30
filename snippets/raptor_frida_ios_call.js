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

	// Call an Objective-C method with arbitrary parameters

	var oldImpl = ObjC.classes.MyClass["+ sendStrings:array:"];

	Interceptor.attach(oldImpl.implementation, {

		onEnter: function(args) {
			console.log("info: entered sendStrings");

			// 1st arg
			var obj = ObjC.Object(args[2]);
			console.log("args[2] type:", obj.$class, obj.$className);
			console.log("args[2] value:", obj.toString());

			// 2nd arg
			var obj = ObjC.Object(args[3]);
			console.log("args[3] type:", obj.$class, obj.$className);
			console.log("args[3] value:", obj.toString());

			// 2nd arg's contents (array)
			for (i = 0; i < obj.count(); i++)
				console.log(ObjC.Object(obj.objectAtIndex_(i)).$class);
		},

		onLeave: function(retval) {
			console.log("info: exiting sendStrings");

			// retval
			var obj = ObjC.Object(retval);
			console.log("retval type:", obj.$class, obj.$className);
			console.log("retval value:", obj.toString());
		}

	});

	// build 1st arg (string)
	// "somestring"
	var arg1 = ObjC.classes.NSString.stringWithString_("somestring");

	// build 2nd arg (NSMutableArray)
	// (
	// "foo",
	// "bar",
	// "someotherstring"
	// )
	var arg2_1 = ObjC.classes.NSString.stringWithString_("foo");
	var arg2_2 = ObjC.classes.NSString.stringWithString_("bar");
	var arg2_3 = ObjC.classes.NSString.stringWithString_("someotherstring");
	var arg2 = ObjC.classes.NSMutableArray.alloc().init();
	arg2.addObject_(arg2_1);
	arg2.addObject_(arg2_2);
	arg2.addObject_(arg2_3);

	// call the target method
	var token = ObjC.classes.MyClass.sendStrings_array_(arg1, arg2);
	console.log(token.toString());

} else {
 	send("error: Objective-C Runtime is not available!");
}
