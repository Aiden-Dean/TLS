# TLS Tester
Over the years now the industry has been trying to deprecate insecure versions of SSL and TLS across the web and there are many great tools out there to help in this process like [IISCrypto](https://www.nartac.com/Products/IISCrypto/), which allows administrators to easily enable/disable protocols and cypher suites on Windows servers.

This is my attempt at furthering this effort by providing a tool that will allow you to test each protocol on a machine to see if you are compliant with industry standards.

In this repo currently is:

- a TLS client console app that will connect to an IP or DNS host on a specified port and attempt to create a secure connection over each available protocol and print the results.
- a TLS server console app that will listen for incoming connections with an SSL certificate and respond only on protocols that are mutually supported

Both can be run from the same machine, across a network or over the internet (providing the port you are listening on is publicly available) depending on your Client/Server protocol requirements.

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
![After](/after.png?raw=true "After")
