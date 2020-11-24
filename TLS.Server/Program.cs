using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using McMaster.Extensions.CommandLineUtils;

namespace TLS.Server
{
    [Command(Description = "A server applet that listens for incoming socket connections to test TLS.")]
    [HelpOption("-?")]
    // ReSharper disable once ClassNeverInstantiated.Global
    internal class Program
    {
        [Option("-cf|--certFile", Description = "The machine certificate to be used to create a secure channel. " +
                                           "Defaults to example cert included in the build.")]
        private string CertificateFile { get; } = Path.Combine(Environment.CurrentDirectory, "example.pfx");

        [Option("-cp|--certPass", Description = "The password to open an encrypted machine certificate.")] 
        private string CertificatePassword { get; } = "test1234";

        private static X509Certificate _certificate;

        [Option("-p|--port", Description = "The port to communicate via. Defaults to 443.")]
        private int Port { get; } = 443;

        private static async Task<int> Main(string[] args) =>
            await CommandLineApplication.ExecuteAsync<Program>(args);

        private async Task<int> OnExecuteAsync(CommandLineApplication app,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(CertificateFile))
            {
                app.ShowHelp();
                return 0;
            }

            _certificate = new X509Certificate(CertificateFile, CertificatePassword);

            var listener = new TcpListener(IPAddress.Any, Port);
            listener.Start();

            while (true)
            {
                Console.WriteLine("Waiting for a client to connect...");
                var client = await listener.AcceptTcpClientAsync();
                await ProcessClientConnectionAsync(client, cancellationToken);
            }
        }

        private static async Task ProcessClientConnectionAsync(TcpClient client, CancellationToken cancellationToken = default)
        {
            var sslStream = new SslStream(client.GetStream(), false);

            try
            {
                await sslStream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificate = _certificate,
                    ClientCertificateRequired = false,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                }, cancellationToken);

                DisplaySecurityLevel(sslStream);
                DisplaySecurityServices(sslStream);
                DisplayCertificateInformation(sslStream);
                DisplayStreamProperties(sslStream);
            }
            catch (Exception e)
            {
                Console.WriteLine("Exception: {0}", e.Message);
                if (e.InnerException != null)
                {
                    Console.WriteLine("Inner exception: {0}", e.InnerException.Message);
                }
                Console.WriteLine ("Authentication failed - closing the connection.");
            }
            finally
            {
                sslStream.Close();
                client.Close();
                Console.WriteLine();
            }
        }

        private static void DisplaySecurityLevel(SslStream stream)
        {
            Console.WriteLine("Cipher: {0} strength {1}", stream.CipherAlgorithm, stream.CipherStrength);
            Console.WriteLine("Hash: {0} strength {1}", stream.HashAlgorithm, stream.HashStrength);
            Console.WriteLine("Key exchange: {0} strength {1}", stream.KeyExchangeAlgorithm,
                stream.KeyExchangeStrength);
            Console.WriteLine("Protocol: {0}", stream.SslProtocol);
        }

        private static void DisplaySecurityServices(AuthenticatedStream stream)
        {
            Console.WriteLine("Is authenticated: {0} as server? {1}", stream.IsAuthenticated, stream.IsServer);
            Console.WriteLine("IsSigned: {0}", stream.IsSigned);
            Console.WriteLine("Is Encrypted: {0}", stream.IsEncrypted);
        }

        private static void DisplayStreamProperties(Stream stream)
        {
            Console.WriteLine("Can read: {0}, write {1}", stream.CanRead, stream.CanWrite);
            Console.WriteLine("Can timeout: {0}", stream.CanTimeout);
        }

        private static void DisplayCertificateInformation(SslStream stream)
        {
            Console.WriteLine("Certificate revocation list checked: {0}", stream.CheckCertRevocationStatus);

            var localCertificate = stream.LocalCertificate;
            if (stream.LocalCertificate != null)
            {
                Console.WriteLine("Local cert was issued to {0} and is valid from {1} until {2}.",
                    localCertificate.Subject,
                    localCertificate.GetEffectiveDateString(),
                    localCertificate.GetExpirationDateString());
            }
            else
            {
                Console.WriteLine("Local certificate is null.");
            }

            // Display the properties of the client's certificate.
            var remoteCertificate = stream.RemoteCertificate;
            if (stream.RemoteCertificate != null)
            {
                Console.WriteLine("Remote cert was issued to {0} and is valid from {1} until {2}.",
                    remoteCertificate?.Subject,
                    remoteCertificate?.GetEffectiveDateString(),
                    remoteCertificate?.GetExpirationDateString());
            }
            else
            {
                Console.WriteLine("Remote certificate is null.");
            }
        }
    }
}