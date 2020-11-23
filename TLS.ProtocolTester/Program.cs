using System;
using System.Collections.Generic;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Threading;
using System.Threading.Tasks;
using McMaster.Extensions.CommandLineUtils;
using Newtonsoft.Json;

namespace TLS.ProtocolTester
{
    [Command(Description = "A simple app to test SSL/TLS protocols for a specified endpoint.")]
    [HelpOption("-?")]
    internal class Program
    {
        private static async Task<int> Main(string[] args) =>
            await CommandLineApplication.ExecuteAsync<Program>(args);

        [Argument(0, Description = "The endpoint to query.")]
        private string Endpoint { get; } = string.Empty;

        [Option("-p|--port", Description = "The port to connect on, defaults to 443.")]
        private int Port { get; } = 443;

        [Option("-c|--certificate", Description = "Specify if you wish to print the X509Certificate details.")]
        private bool ShowCertificate { get; } = false;

        // todo: add verbose logging
        //[Option("-v|--verbose")] private bool Verbose { get; } = false;

        private async Task<int> OnExecuteAsync(CommandLineApplication app, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(Endpoint))
            {
                app.ShowHelp();
                return 0;
            }

            var status = new ProtocolStatus
            {
                Endpoint = Endpoint,
                Port = Port
            };

            foreach (SslProtocols protocol in Enum.GetValues(typeof(SslProtocols)))
            {
                var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);

                try
                {
                    await socket.ConnectAsync(Endpoint, Port);
                    status.ConnectionSuccessful = true;
                }
                catch
                {
                    status.ConnectionSuccessful = false;
                    return 0;
                }

                var netStream = new NetworkStream(socket, true);
                var sslStream = new SslStream(netStream, true);

                try
                {
                    await sslStream.AuthenticateAsClientAsync(Endpoint, null, protocol, false);

                    if (ShowCertificate)
                    {
                        status.Certificate = new Certificate
                        {
                            Subject = sslStream.RemoteCertificate?.Subject,
                            Issuer = sslStream.RemoteCertificate?.Issuer,
                            NotBefore = sslStream.RemoteCertificate?.GetEffectiveDateString(),
                            NotAfter = sslStream.RemoteCertificate?.GetExpirationDateString(),
                        };
                    }

                    status.Protocols.Add(protocol, true);
                }
                catch
                {
                    status.Protocols.Add(protocol, false);
                }
                finally
                {
                    sslStream.Close();
                }
            }
            
            Console.WriteLine(JsonConvert.SerializeObject(status, Formatting.Indented));
            
            return 1;
        }
    }

    internal class ProtocolStatus
    {
        public string Endpoint { get; set; }
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