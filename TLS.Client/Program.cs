using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using McMaster.Extensions.CommandLineUtils;
using Newtonsoft.Json;

namespace TLS.Client
{
    [Command(Description = "A simple app to test SSL/TLS protocols for a specified endpoint.")]
    [HelpOption("-?")]
    internal class Program
    {
        [Option("-t|--target", Description = "The target endpoint to query. Defaults to 127.0.0.1")]
        private string TargetEndpoint { get; } = IPAddress.Loopback.MapToIPv4().ToString();

        [Option("-p|--port", Description = "The port to connect on. Defaults to 443.")]
        private int Port { get; } = 443;

        [Option("-v|--verbose")] private bool Verbose { get; } = false;

        private static async Task<int> Main(string[] args) =>
            await CommandLineApplication.ExecuteAsync<Program>(args);

        private async Task<int> OnExecuteAsync(CommandLineApplication app,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(TargetEndpoint))
            {
                app.ShowHelp();
                return 0;
            }

            if (Verbose)
            {
                Console.WriteLine("Starting TLS.Client app...\n");
            }

            var status = new ProtocolStatus
            {
                TargetEndpoint = TargetEndpoint,
                Port = Port
            };

            if (Verbose)
                Console.WriteLine("Testing against list of known protocols.\n");

            foreach (SslProtocols protocol in Enum.GetValues(typeof(SslProtocols)))
            {
                if (Verbose)
                {
                    Console.WriteLine("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-");
                    Console.WriteLine($"Begin building test for protocol [{protocol}]");
                }

                var client = new TcpClient();

                try
                {
                    if (Verbose)
                        Console.WriteLine($"Attempting to connect to [{TargetEndpoint}:{Port}]");

                    await client.ConnectAsync(TargetEndpoint, Port);
                    status.ConnectionSuccessful = true;
                    if (Verbose)
                        Console.WriteLine(
                            $"Connection [{(status.ConnectionSuccessful ? "Successful" : "Unsuccessful")}]");
                }
                catch
                {
                    status.ConnectionSuccessful = false;

                    if (Verbose)
                        Console.WriteLine(
                            $"Connection [{(status.ConnectionSuccessful ? "Successful" : "Unsuccessful")}]");

                    return 0;
                }

                if (Verbose)
                    Console.WriteLine("Creating SSL/TLS connection stream");

                var sslStream = new SslStream(client.GetStream(), false);

                try
                {
                    if (Verbose)
                        Console.WriteLine($"Attempting to authenticate as a client via protocol [{protocol}]");

                    await sslStream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                    {
                        TargetHost = TargetEndpoint,
                        EnabledSslProtocols = protocol,
                        CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                        RemoteCertificateValidationCallback = RemoteCertificateValidationCallback
                    }, cancellationToken);

                    //sslStream.AuthenticateAsClient(Endpoint, null, protocol, false);

                    if (Verbose)
                    {
                        Console.WriteLine(
                            $"Authentication [{(sslStream.IsAuthenticated ? "Successful" : "Unsuccessful")}]");
                        Console.WriteLine("Gathering certificate details");
                    }

                    status.Certificate = new Certificate
                    {
                        Subject = sslStream.RemoteCertificate?.Subject,
                        Issuer = sslStream.RemoteCertificate?.Issuer,
                        NotBefore = sslStream.RemoteCertificate?.GetEffectiveDateString(),
                        NotAfter = sslStream.RemoteCertificate?.GetExpirationDateString(),
                    };

                    if (Verbose)
                        Console.WriteLine($"Adding successful attempt for protocol [{protocol}]");

                    status.Protocols.Add(protocol, true);
                }
                catch (AuthenticationException e)
                {
                    if (Verbose)
                    {
                        Console.WriteLine("Exception: {0}", e.Message);
                        if (e.InnerException != null)
                        {
                            Console.WriteLine("Inner exception: {0}", e.InnerException.Message);
                        }
                        Console.WriteLine ("Authentication failed - closing the connection.");
                        Console.WriteLine($"Adding unsuccessful attempt for protocol [{protocol}]");
                    }

                    status.Protocols.Add(protocol, false);
                }
                finally
                {
                    if (Verbose)
                        Console.WriteLine("Closing the SSL/TLS connection stream");

                    sslStream.Close();

                    if (Verbose)
                        Console.WriteLine("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-\n");
                }
            }

            Console.WriteLine(JsonConvert.SerializeObject(status, Formatting.Indented));

            return 1;
        }

        private static bool RemoteCertificateValidationCallback(object sender, X509Certificate certificate,
            X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            // we do not care if the cert is invalid right now
            return true;
        }
    }

    internal class ProtocolStatus
    {
        public string TargetEndpoint { get; set; }
        public int Port { get; set; }
        public bool ConnectionSuccessful { get; set; }
        public Dictionary<SslProtocols, bool> Protocols { get; } = new Dictionary<SslProtocols, bool>();
        public Certificate Certificate { get; set; }
    }

    internal class Certificate
    {
        public string Subject { get; set; }
        public string Issuer { get; set; }
        public string NotBefore { get; set; }
        public string NotAfter { get; set; }
    }
}