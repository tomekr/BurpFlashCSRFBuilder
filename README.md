## Description

This is a Burp extension that is a wrapper around TheRook's
[CSRF-Request-Builder](https://github.com/TheRook/CSRF-Request-Builder).
More information can be found on his Github page.

For more information on CORS requests, see Mozilla's writeup on [HTTP
Access Control
(CORS)](https://developer.mozilla.org/en-US/docs/HTTP/Access_control_CORS)

## Features
- Generates HTML & SWF file to use as proof of concept
- Automatically removes blacklisted headers from request
- Preflight Status Check 
- Add/Remove Headers
- Headers which will require a preflight request are highlighted in
yellow

## Usage

1. Right click on any request within Burp.
2. In the context menu, click on "Generate Flash CSRF PoC".
3. Make any necessary adjustments.
4. Choose where you would like to save the proof of concept files (two
   files, csrf_poc.html and csrf.swf will be generated).
5. Click the Generate button.

## Installation

1. Add the BurpFlashCSRFBuilder-0.1.4.jar located in the target folder
   to the list of extensions located in the Burp Extender tab.

## Screenshots

![Menu](http://github.com/tomekr/BurpFlashCSRFBuilder/raw/master/screenshots/menu.png)

![UI](http://github.com/tomekr/BurpFlashCSRFBuilder/raw/master/screenshots/ui.png)

## TODO:

- Ensure that added headers are not in the blacklist
- Add help icon to explain a preflight
- Add a help icon to show blacklisted headers
 
