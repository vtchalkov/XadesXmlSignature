using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace XadesXmlSignature.Tests;

internal static class TestCertificateHelper
{
    public static (X509Certificate2 rootCert, X509Certificate2 signCert) CreateTestCertificates()
    {
        using var rootKey = RSA.Create(2048);
        var rootReq = new CertificateRequest("CN=Test Root CA", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));

        var rootCert = rootReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));

        using var signKey = RSA.Create(2048);
        var signReq = new CertificateRequest("CN=Test Signer", signKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        signReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        signReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, true));

        var serialNumber = new byte[16];
        RandomNumberGenerator.Fill(serialNumber);
        serialNumber[0] &= 0x7F; // ensure positive

        var signCertPub = signReq.Create(rootCert, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(2), serialNumber);

        // Attach private key
        var signCertWithKey = signCertPub.CopyWithPrivateKey(signKey);

        // Export/import to get a fully usable cert (required on Windows)
        var pfxBytes = signCertWithKey.Export(X509ContentType.Pfx, "test");
        var finalSignCert = new X509Certificate2(pfxBytes, "test", X509KeyStorageFlags.Exportable);

        var rootPfx = rootCert.Export(X509ContentType.Pfx, "test");
        var finalRootCert = new X509Certificate2(rootPfx, "test", X509KeyStorageFlags.Exportable);

        return (finalRootCert, finalSignCert);
    }
}
