using FirmaXadesNet;
using FirmaXadesNet.Clients;
using FirmaXadesNet.Crypto;
using FirmaXadesNet.Signature;
using FirmaXadesNet.Signature.Parameters;
using FirmaXadesNet.Upgraders;
using FirmaXadesNet.Upgraders.Parameters;
using System.Security.Cryptography.X509Certificates;

namespace XadesXmlSignature.Console;

class Program
{
    static void Main(string[] args)
    {
        System.Console.WriteLine("=== XAdES XML Signature Test Console ===");
        System.Console.WriteLine();

        while (true)
        {
            System.Console.WriteLine("Select an operation:");
            System.Console.WriteLine("  1. Sign an XML file (enveloped)");
            System.Console.WriteLine("  2. Sign an XML file (internally detached)");
            System.Console.WriteLine("  3. Load and validate a signed XML file");
            System.Console.WriteLine("  4. Upgrade signature to XAdES-T");
            System.Console.WriteLine("  5. Upgrade signature to XAdES-XL");
            System.Console.WriteLine("  6. Upgrade signature to XAdES-A");
            System.Console.WriteLine("  7. Save current signature");
            System.Console.WriteLine("  0. Exit");
            System.Console.Write("> ");

            var choice = System.Console.ReadLine()?.Trim();
            System.Console.WriteLine();

            try
            {
                switch (choice)
                {
                    case "1":
                        SignEnveloped();
                        break;
                    case "2":
                        SignInternallyDetached();
                        break;
                    case "3":
                        LoadAndValidate();
                        break;
                    case "4":
                        UpgradeSignature(SignatureFormat.XAdES_T);
                        break;
                    case "5":
                        UpgradeSignature(SignatureFormat.XAdES_XL);
                        break;
                    case "6":
                        UpgradeSignature(SignatureFormat.XAdES_A);
                        break;
                    case "7":
                        SaveSignature();
                        break;
                    case "0":
                        return;
                    default:
                        System.Console.WriteLine("Invalid choice.");
                        break;
                }
            }
            catch (Exception ex)
            {
                System.Console.WriteLine($"ERROR: {ex.Message}");
                if (ex.InnerException != null)
                    System.Console.WriteLine($"  Inner: {ex.InnerException.Message}");
            }

            System.Console.WriteLine();
        }
    }

    static SignatureDocument? _currentSignature;

    static X509Certificate2? SelectCertificate()
    {
        var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);

        var certs = store.Certificates.Find(X509FindType.FindByTimeValid, DateTime.Now, false);

        if (certs.Count == 0)
        {
            System.Console.WriteLine("No valid certificates found in the current user store.");
            store.Close();
            return null;
        }

        System.Console.WriteLine("Available certificates:");
        for (int i = 0; i < certs.Count; i++)
        {
            var cert = certs[i];
            System.Console.WriteLine($"  [{i}] {cert.Subject} (Thumbprint: {cert.Thumbprint[..8]}...)");
        }

        System.Console.Write("Select certificate number: ");
        if (int.TryParse(System.Console.ReadLine()?.Trim(), out int idx) && idx >= 0 && idx < certs.Count)
        {
            var selected = certs[idx];
            if (!selected.HasPrivateKey)
            {
                System.Console.WriteLine("Selected certificate does not have a private key.");
                store.Close();
                return null;
            }
            store.Close();
            return selected;
        }

        System.Console.WriteLine("Invalid selection.");
        store.Close();
        return null;
    }

    static void SignEnveloped()
    {
        System.Console.Write("Path to XML file: ");
        var filePath = System.Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
        {
            System.Console.WriteLine("File not found.");
            return;
        }

        var cert = SelectCertificate();
        if (cert == null) return;

        var xadesService = new XadesService();
        var parameters = new SignatureParameters
        {
            SignatureMethod = SignatureMethod.RSAwithSHA256,
            SigningDate = DateTime.Now,
            SignaturePackaging = SignaturePackaging.ENVELOPED,
            InputMimeType = "text/xml"
        };
        parameters.SignatureCommitments.Add(new SignatureCommitment(SignatureCommitmentType.ProofOfOrigin));

        using (parameters.Signer = new Signer(cert))
        using (var fs = new FileStream(filePath, FileMode.Open))
        {
            _currentSignature = xadesService.Sign(fs, parameters);
        }

        System.Console.WriteLine("Enveloped signature created successfully.");
    }

    static void SignInternallyDetached()
    {
        System.Console.Write("Path to file: ");
        var filePath = System.Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
        {
            System.Console.WriteLine("File not found.");
            return;
        }

        System.Console.Write("MIME type (e.g., text/xml, application/pdf): ");
        var mimeType = System.Console.ReadLine()?.Trim() ?? "text/xml";

        var cert = SelectCertificate();
        if (cert == null) return;

        var xadesService = new XadesService();
        var parameters = new SignatureParameters
        {
            SignatureMethod = SignatureMethod.RSAwithSHA256,
            SigningDate = DateTime.Now,
            SignaturePackaging = SignaturePackaging.INTERNALLY_DETACHED,
            InputMimeType = mimeType
        };
        parameters.SignatureCommitments.Add(new SignatureCommitment(SignatureCommitmentType.ProofOfOrigin));

        using (parameters.Signer = new Signer(cert))
        using (var fs = new FileStream(filePath, FileMode.Open))
        {
            _currentSignature = xadesService.Sign(fs, parameters);
        }

        System.Console.WriteLine("Internally detached signature created successfully.");
    }

    static void LoadAndValidate()
    {
        System.Console.Write("Path to signed XML file: ");
        var filePath = System.Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
        {
            System.Console.WriteLine("File not found.");
            return;
        }

        var xadesService = new XadesService();
        using var fs = new FileStream(filePath, FileMode.Open);
        var signatures = xadesService.Load(fs);

        System.Console.WriteLine($"Found {signatures.Length} signature(s).");

        for (int i = 0; i < signatures.Length; i++)
        {
            var result = xadesService.Validate(signatures[i]);
            System.Console.WriteLine($"  Signature [{i}]: {(result.IsValid ? "VALID" : "INVALID")} - {result.Message}");
        }

        if (signatures.Length > 0)
        {
            _currentSignature = signatures[0];
            System.Console.WriteLine("First signature loaded as current.");
        }
    }

    static void UpgradeSignature(SignatureFormat format)
    {
        if (_currentSignature == null)
        {
            System.Console.WriteLine("No signature loaded. Sign or load a document first.");
            return;
        }

        System.Console.Write("Timestamp server URL (e.g., http://timestamp.digicert.com): ");
        var tsaUrl = System.Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(tsaUrl))
        {
            System.Console.WriteLine("Timestamp URL is required.");
            return;
        }

        var upgradeParams = new UpgradeParameters
        {
            TimeStampClient = new TimeStampClient(tsaUrl)
        };

        if (format == SignatureFormat.XAdES_XL || format == SignatureFormat.XAdES_A)
        {
            System.Console.Write("OCSP server URL (leave empty to use certificate AIA): ");
            var ocspUrl = System.Console.ReadLine()?.Trim();
            if (!string.IsNullOrEmpty(ocspUrl))
            {
                upgradeParams.OCSPServers.Add(new OcspServer(ocspUrl));
            }
        }

        var upgrader = new XadesUpgraderService();
        upgrader.Upgrade(_currentSignature, format, upgradeParams);

        System.Console.WriteLine($"Signature upgraded to {format} successfully.");
    }

    static void SaveSignature()
    {
        if (_currentSignature == null)
        {
            System.Console.WriteLine("No signature loaded.");
            return;
        }

        System.Console.Write("Output file path: ");
        var path = System.Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(path))
        {
            System.Console.WriteLine("Path is required.");
            return;
        }

        _currentSignature.Save(path);
        System.Console.WriteLine($"Signature saved to {path}.");
    }
}
