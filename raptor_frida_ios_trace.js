/*
 * raptor_frida_ios_trace.js - ObjC & Module tracer for iOS
 * Copyright (c) 2017 Marco Ivaldi <raptor@0xdeadbeef.info>
 *
 * Frida.re JS script to trace arbitrary ObjC methods and
 * Module functions for debugging and reverse engineering.
 * See https://www.frida.re/ and https://codeshare.frida.re/
 * for further information on this powerful tool.
 *
 * "We want to help others achieve interop through reverse
 * engineering" -- @oleavr
 *
 * Many thanks to @inode-, @federicodotta, @mrmacete, and
 * @dankluev.
 *
 * Example usage:
 * # frida -U -f com.target.app -l raptor_frida_ios_trace.js --no-pause
 *
 * Get the latest version at:
 * https://github.com/0xdea/frida-scripts/
 */

// generic trace
function trace(pattern)
{
	var type = (pattern.indexOf(" ") === -1) ? "module" : "objc";
	var res = new ApiResolver(type);
	var matches = res.enumerateMatchesSync(pattern);
	var targets = uniqBy(matches, JSON.stringify);

	targets.forEach(function(target) {
		if (type === "objc")
			traceObjC(target.address, target.name);
		else if (type === "module")
			traceModule(target.address, target.name);
	});
}

// remove duplicates from array
function uniqBy(array, key) 
{
	var seen = {};
	return array.filter(function(item) {
		var k = key(item);
		return seen.hasOwnProperty(k) ? false : (seen[k] = true);
	});
}

// trace ObjC methods
function traceObjC(impl, name)
{
	console.log("Tracing " + name);

	Interceptor.attach(impl, {

		onEnter: function(args) {

			// debug only the intended calls
			this.flag = 0;
			// if (ObjC.Object(args[2]).toString() === "1234567890abcdef1234567890abcdef12345678")
				this.flag = 1;

			if (this.flag) {
				console.warn("\n*** entered " + name);

				// print full backtrace
				// console.log("\nBacktrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE)
				//		.map(DebugSymbol.fromAddress).join("\n"));

				// print caller
				console.log("\nCaller: " + DebugSymbol.fromAddress(this.returnAddress));

				// print args
				if (name.indexOf(":") !== -1) {
					console.log();
					var par = name.split(":");
					par[0] = par[0].split(" ")[1];
					for (var i = 0; i < par.length - 1; i++)
						printArg(par[i] + ": ", args[i + 2]);
				}
			}
		},

		onLeave: function(retval) {

			if (this.flag) {
				// print retval
				printArg("\nretval: ", retval);
				console.warn("\n*** exiting " + name);
			}
		}

	});
}

// trace Module functions
function traceModule(impl, name)
{
	console.log("Tracing " + name);

	Interceptor.attach(impl, {

		onEnter: function(args) {

			// debug only the intended calls
			this.flag = 0;
			// var filename = Memory.readCString(ptr(args[0]));
			// if (filename.indexOf("Bundle") === -1 && filename.indexOf("Cache") === -1) // exclusion list
			// if (filename.indexOf("my.interesting.file") !== -1) // inclusion list
				this.flag = 1;

			if (this.flag) {
				console.warn("\n*** entered " + name);

				// print backtrace
				console.log("\nBacktrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE)
						.map(DebugSymbol.fromAddress).join("\n"));
			}
		},

		onLeave: function(retval) {

			if (this.flag) {
				// print retval
				printArg("\nretval: ", retval);
				console.warn("\n*** exiting " + name);
			}
		}

	});
}

// print helper
function printArg(desc, arg)
{
	try {
		console.log(desc + ObjC.Object(arg));
	}
	catch(err) {
		console.log(desc + arg);
	}
}

// usage examples
if (ObjC.available) {

	// trace("-[CredManager setPassword:]");
	// trace("*[CredManager *]");
	// trace("*[* *Password:*]");
	// trace("exports:libSystem.B.dylib!CCCrypt");
	// trace("exports:libSystem.B.dylib!open");
	// trace("exports:*!open*");
	
} else {
 	send("error: Objective-C Runtime is not available!");
}
