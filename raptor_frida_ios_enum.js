/*
 * raptor_frida_ios_enum.js - ObjC class/method enumerator
 * Copyright (c) 2017 Marco Ivaldi <raptor@0xdeadbeef.info>
 *
 * Frida.re JS functions to enumerate ObjC classes and
 * methods declared in an iOS app. See https://www.frida.re/ 
 * and https://codeshare.frida.re/ for further information on 
 * this powerful tool.
 *
 * "We want to help others achieve interop through reverse
 * engineering" -- @oleavr
 *
 * Example usage:
 * # frida -U -f com.target.app -l raptor_frida_ios_enum.js --no-pause
 *
 * Get the latest version at:
 * https://github.com/0xdea/frida-scripts/
 */

// enumerate all ObjC classes
function enumAllClasses()
{
	var allClasses = [];

	for (var aClass in ObjC.classes) {
		if (ObjC.classes.hasOwnProperty(aClass)) {
			allClasses.push(aClass);
		}
	}

	return allClasses;
}

// find all ObjC classes that match a pattern
function findClasses(pattern)
{
	var allClasses = enumAllClasses();
	var foundClasses = [];

	allClasses.forEach(function(aClass) {
		if (aClass.match(pattern)) {
			foundClasses.push(aClass);
		}
	});

	return foundClasses;
}

// enumerate all methods declared in an ObjC class
function enumMethods(targetClass)
{
	var ownMethods = ObjC.classes[targetClass].$ownMethods;

	return ownMethods;
}

// enumerate all methods declared in all ObjC classes
function enumAllMethods()
{
	var allClasses = enumAllClasses();
	var allMethods = {}; 

	allClasses.forEach(function(aClass) {
		enumMethods(aClass).forEach(function(method) {
			if (!allMethods[aClass]) allMethods[aClass] = [];
			allMethods[aClass].push(method);
		});
	});

	return allMethods;
}

// find all ObjC methods that match a pattern
function findMethods(pattern)
{
	var allMethods = enumAllMethods();
	var foundMethods = {};

	for (var aClass in allMethods) {
		allMethods[aClass].forEach(function(method) {
			if (method.match(pattern)) {
				if (!foundMethods[aClass]) foundMethods[aClass] = [];
				foundMethods[aClass].push(method);
			}
		});
	}

	return foundMethods;
}

// usage examples
if (ObjC.available) {

	// enumerate all classes
	/*
	var a = enumAllClasses();
	a.forEach(function(s) { 
		console.log(s); 
	});
	*/

	// find classes that match a pattern
	/*
	var a = findClasses(/password/i);
	a.forEach(function(s) { 
		console.log(s); 
	});
	*/

	// enumerate all methods in a class
	/*
	var a = enumMethods("PasswordManager")
	a.forEach(function(s) { 
		console.log(s); 
	});
	*/

	// enumerate all methods
	/*
	var d = enumAllMethods();
	for (k in d) {
		console.log(k);
		d[k].forEach(function(s) {
			console.log("\t" + s);
		});
	}
	*/

	// find methods that match a pattern
	/*
	var d = findMethods(/password/i);
	for (k in d) {
		console.log(k);
		d[k].forEach(function(s) {
			console.log("\t" + s);
		});
	}
	*/

} else {
 	send("error: Objective-C Runtime is not available!");
}
