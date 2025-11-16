/*
 * raptor_frida_android_enum.js - Java class and method enumerator
 * Copyright (c) 2017-2025 Marco Ivaldi <raptor@0xdeadbeef.info>
 *
 * "For all is like an ocean, all flows and connects; 
 * touch it in one place and it echoes at the other end of the world."
 *                        -- Fyodor Dostoevsky, The Brothers Karamazov
 * 
 * Frida.re JS code to enumerate Java classes and methods declared in an 
 * Android app. See https://www.frida.re/ and https://codeshare.frida.re/ for 
 * further information on this world-class dynamic instrumentation toolkit.
 *
 * Example usage:
 * $ uv tool install frida-tools
 * $ frida -U -f com.target.app -l raptor_frida_android_enum.js
 *
 * Tested with:
 * Frida 17.3.2 on macOS 15.6.1 with Redmi Note 10S (Android 11)
 *
 * Get the latest version at:
 * https://github.com/0xdea/frida-scripts/
 */

// Enumerate all Java classes
function enumAllClasses()
{
	var allClasses = [];
	var classes = Java.enumerateLoadedClassesSync();

	classes.forEach(function(aClass) {
		try {
			var className = aClass.match(/[L](.*);/)[1].replace(/\//g, ".");
		}
		catch(err) {return;} // Avoid TypeError: cannot read property 1 of null
		allClasses.push(className);
	});

	return allClasses;
}

// Find all Java classes that match a pattern
function findClasses(pattern)
{
	var allClasses = enumAllClasses();
	var foundClasses = [];

	allClasses.forEach(function(aClass) {
		try {
			if (aClass.match(pattern)) {
				foundClasses.push(aClass);
			}
		}
		catch(err) {} // Avoid TypeError: cannot read property 'match' of undefined
	});

	return foundClasses;
}

// Enumerate all methods declared in a Java class
function enumMethods(targetClass)
{
	var hook = Java.use(targetClass);
	var ownMethods = hook.class.getDeclaredMethods();
	hook.$dispose;

	return ownMethods;
}

/*
 * The following functions were not implemented because deemed impractical:
 *
 * enumAllMethods() - enumerate all methods declared in all Java classes
 * findMethods(pattern) - find all Java methods that match a pattern
 *
 * See raptor_frida_ios_enum.js for a couple of ObjC implementation examples.
 */

// Usage examples
setTimeout(function() { // Avoid java.lang.ClassNotFoundException

	Java.perform(function() {

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
		var a = enumMethods("com.target.app.PasswordManager")
		a.forEach(function(s) { 
			console.log(s); 
		});
		*/

	});
}, 0);
