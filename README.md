# TLS Tester
Over the years now I keep being asked how we can test if the various versions of SSL and TLS are truly
disabled on a machine. 

Through [IISCrypto](https://www.nartac.com/Products/IISCrypto/), administrators have the ability to
disable/enable protocols and cypher suites but testing if it has worked or not requires an application
running on the server to test against which might not always be available or it may be too late to check
when the service is degraded beyond use.

This is my attempt at an answer to this problem, a client applet which will try to create a connection
to a specified endpoint (IP or DNS), open an SSL stream and print out the results.
Along with it comes a server applet which listens for incoming connections on a specified port in the event
that you do not have an accessible endpoint on the machine to test against.

## Usage
**TLS.Client**
```
TLS.Client -?
A simple app to test SSL/TLS protocols for a specified endpoint.

Usage: TLS.Client [options]

Options:
  -?                  Show help information
  -t|--target         The target endpoint to query. Defaults to 127.0.0.1
  -p|--port           The port to connect on. Defaults to 443.
  -l|--logEventLevel  The verbosity of the output from the app processing. Defaults to [Information]
```

**TLS.Server**
```
TLS.Server -?
A server applet that listens for incoming socket connections to test TLS.

Usage: TLS.Server [options]

Options:
  -?                  Show help information
  -cf|--certFile      The machine certificate to be used to create a secure channel. Defaults to example cert included in the build.
  -cp|--certPass      The password to open an encrypted machine certificate.
  -p|--port           The port to communicate via. Defaults to 443.
  -l|--logEventLevel  The verbosity of the output from the app processing. Defaults to [Information]
```

## Images
![Before](/before.png?raw=true "Before")
