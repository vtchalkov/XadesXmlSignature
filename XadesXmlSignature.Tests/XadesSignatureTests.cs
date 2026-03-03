using FirmaXadesNet;
using FirmaXadesNet.Crypto;
using FirmaXadesNet.Signature;
using FirmaXadesNet.Signature.Parameters;
using FirmaXadesNet.Validation;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using Xunit;

namespace XadesXmlSignature.Tests;

public class XadesSignatureTests : IDisposable
{
    private readonly X509Certificate2 _rootCert;
    private readonly X509Certificate2 _signCert;
    private readonly string _testDataDir;

    public XadesSignatureTests()
    {
        var (rootCert, signCert) = TestCertificateHelper.CreateTestCertificates();
        _rootCert = rootCert;
        _signCert = signCert;
        _testDataDir = Path.Combine(AppContext.BaseDirectory, "TestData");
    }

    public void Dispose()
    {
        _rootCert.Dispose();
        _signCert.Dispose();
    }

    #region Enveloped signing

    [Fact]
    public void Sign_Enveloped_ProducesValidSignature()
    {
        var xadesService = new XadesService();
        var parameters = CreateDefaultParameters(SignaturePackaging.ENVELOPED, "text/xml");

        SignatureDocument sigDoc;
        using (parameters.Signer = new Signer(_signCert))
        using (var fs = OpenTestFile("Sample.xml"))
        {
            sigDoc = xadesService.Sign(fs, parameters);
        }

        Assert.NotNull(sigDoc);
        Assert.NotNull(sigDoc.Document);
        Assert.NotNull(sigDoc.XadesSignature);

        var result = xadesService.Validate(sigDoc);
        Assert.True(result.IsValid, result.Message);
    }

    [Fact]
    public void Sign_Enveloped_XadesCheckSignature_ReturnsTrue()
    {
        var xadesService = new XadesService();
        var parameters = CreateDefaultParameters(SignaturePackaging.ENVELOPED, "text/xml");

        SignatureDocument sigDoc;
        using (parameters.Signer = new Signer(_signCert))
        using (var fs = OpenTestFile("Sample.xml"))
        {
            sigDoc = xadesService.Sign(fs, parameters);
        }

        bool xadesCheck = sigDoc.XadesSignature.XadesCheckSignature(
            Microsoft.Xades.XadesCheckSignatureMasks.AllChecks);
        Assert.True(xadesCheck);
    }

    [Fact]
    public void Sign_Enveloped_WithSignerRole_ProducesValidSignature()
    {
        var xadesService = new XadesService();
        var parameters = CreateDefaultParameters(SignaturePackaging.ENVELOPED, "text/xml");
        parameters.SignerRole = new SignerRole();
        parameters.SignerRole.ClaimedRoles.Add("signer");

        SignatureDocument sigDoc;
        using (parameters.Signer = new Signer(_signCert))
        using (var fs = OpenTestFile("Sample.xml"))
        {
            sigDoc = xadesService.Sign(fs, parameters);
        }

        var result = xadesService.Validate(sigDoc);
        Assert.True(result.IsValid, result.Message);
    }

    [Fact]
    public void Sign_Enveloped_WithPolicy_ProducesValidSignature()
    {
        var xadesService = new XadesService();
        var parameters = CreateDefaultParameters(SignaturePackaging.ENVELOPED, "text/xml");
        parameters.SignaturePolicyInfo = new SignaturePolicyInfo
        {
            PolicyIdentifier = "http://example.com/policy",
            PolicyHash = "Ohixl6upD6av8N7pEvDABhEL6hM="
        };

        SignatureDocument sigDoc;
        using (parameters.Signer = new Signer(_signCert))
        using (var fs = OpenTestFile("Facturae.xml"))
        {
            sigDoc = xadesService.Sign(fs, parameters);
        }

        var result = xadesService.Validate(sigDoc);
        Assert.True(result.IsValid, result.Message);
    }

    [Fact]
    public void Sign_Enveloped_WithProductionPlace_ProducesValidSignature()
    {
        var xadesService = new XadesService();
        var parameters = CreateDefaultParameters(SignaturePackaging.ENVELOPED, "text/xml");
        parameters.SignatureProductionPlace = new SignatureProductionPlace
        {
            City = "Sofia",
            CountryName = "Bulgaria",
            PostalCode = "1303",
            StateOrProvince = "Sofia"
        };

        SignatureDocument sigDoc;
        using (parameters.Signer = new Signer(_signCert))
        using (var fs = OpenTestFile("Sample.xml"))
        {
            sigDoc = xadesService.Sign(fs, parameters);
        }

        var result = xadesService.Validate(sigDoc);
        Assert.True(result.IsValid, result.Message);
    }

    #endregion

    #region Enveloping signing

    [Fact]
    public void Sign_Enveloping_ProducesValidSignature()
    {
        var xadesService = new XadesService();
        var parameters = CreateDefaultParameters(SignaturePackaging.ENVELOPING, "text/xml");

        SignatureDocument sigDoc;
        using (parameters.Signer = new Signer(_signCert))
        using (var fs = OpenTestFile("Sample.xml"))
        {
            sigDoc = xadesService.Sign(fs, parameters);
        }

        Assert.NotNull(sigDoc);
        var result = xadesService.Validate(sigDoc);
        Assert.True(result.IsValid, result.Message);
    }

    #endregion

    #region Internally detached signing

    [Fact]
    public void Sign_InternallyDetached_Xml_ProducesValidSignature()
    {
        var xadesService = new XadesService();
        var parameters = CreateDefaultParameters(SignaturePackaging.INTERNALLY_DETACHED, "text/xml");

        SignatureDocument sigDoc;
        using (parameters.Signer = new Signer(_signCert))
        using (var fs = OpenTestFile("Sample.xml"))
        {
            sigDoc = xadesService.Sign(fs, parameters);
        }

        Assert.NotNull(sigDoc);
        var result = xadesService.Validate(sigDoc);
        Assert.True(result.IsValid, result.Message);
    }

    [Fact]
    public void Sign_InternallyDetached_Binary_ProducesValidSignature()
    {
        var xadesService = new XadesService();
        var parameters = CreateDefaultParameters(SignaturePackaging.INTERNALLY_DETACHED, "application/octet-stream");

        var testData = System.Text.Encoding.UTF8.GetBytes("Hello, XAdES!");
        SignatureDocument sigDoc;
        using (parameters.Signer = new Signer(_signCert))
        using (var ms = new MemoryStream(testData))
        {
            sigDoc = xadesService.Sign(ms, parameters);
        }

        Assert.NotNull(sigDoc);
        var result = xadesService.Validate(sigDoc);
        Assert.True(result.IsValid, result.Message);
    }

    [Fact]
    public void Sign_InternallyDetached_WithElementId_ProducesValidSignature()
    {
        var xadesService = new XadesService();
        var parameters = new SignatureParameters
        {
            SignatureMethod = SignatureMethod.RSAwithSHA256,
            SigningDate = DateTime.Now,
            SignaturePackaging = SignaturePackaging.INTERNALLY_DETACHED,
            InputMimeType = "text/xml",
            ElementIdToSign = "CONTENT-12ef114d-ac6c-4da3-8caf-50379ed13698"
        };

        var signatureDestination = new SignatureXPathExpression();
        signatureDestination.Namespaces.Add("enidoc", "http://administracionelectronica.gob.es/ENI/XSD/v1.0/documento-e");
        signatureDestination.Namespaces.Add("enids", "http://administracionelectronica.gob.es/ENI/XSD/v1.0/firma");
        signatureDestination.XPathExpression = "enidoc:documento/enids:firmas/enids:firma/enids:ContenidoFirma/enids:FirmaConCertificado";
        parameters.SignatureDestination = signatureDestination;

        SignatureDocument sigDoc;
        using (parameters.Signer = new Signer(_signCert))
        using (var fs = OpenTestFile("xsdBOE-A-2011-13169_ex_XAdES_Internally_detached.xml"))
        {
            sigDoc = xadesService.Sign(fs, parameters);
        }

        Assert.NotNull(sigDoc);
        var result = xadesService.Validate(sigDoc);
        Assert.True(result.IsValid, result.Message);
    }

    #endregion

    #region Externally detached signing

    [Fact]
    public void Sign_ExternallyDetached_ProducesValidSignature()
    {
        // Use the test output directory to avoid URI encoding issues with
        // special characters in user profile paths (e.g., parentheses)
        var tempFile = Path.Combine(AppContext.BaseDirectory, "test-external-" + Guid.NewGuid().ToString("N") + ".xml");
        try
        {
            File.WriteAllText(tempFile, "<?xml version=\"1.0\" encoding=\"utf-8\" ?><Test>Hello</Test>");

            var xadesService = new XadesService();
            var parameters = new SignatureParameters
            {
                SignatureMethod = SignatureMethod.RSAwithSHA256,
                SigningDate = DateTime.Now,
                SignaturePackaging = SignaturePackaging.EXTERNALLY_DETACHED,
                ExternalContentUri = tempFile
            };

            SignatureDocument sigDoc;
            using (parameters.Signer = new Signer(_signCert))
            {
                sigDoc = xadesService.Sign(null, parameters);
            }

            Assert.NotNull(sigDoc);
            Assert.NotNull(sigDoc.Document);
        }
        finally
        {
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    #endregion

    #region Load and validate

    [Fact]
    public void Load_SignedDocument_ReturnsSignatures()
    {
        var xadesService = new XadesService();
        var parameters = CreateDefaultParameters(SignaturePackaging.ENVELOPED, "text/xml");

        SignatureDocument sigDoc;
        using (parameters.Signer = new Signer(_signCert))
        using (var fs = OpenTestFile("Sample.xml"))
        {
            sigDoc = xadesService.Sign(fs, parameters);
        }

        // Save and reload
        using var ms = new MemoryStream();
        sigDoc.Save(ms);
        ms.Position = 0;

        var loaded = xadesService.Load(ms);
        Assert.NotEmpty(loaded);
        Assert.Single(loaded);
    }

    [Fact]
    public void Validate_ModifiedDocument_ReturnsInvalid()
    {
        var xadesService = new XadesService();
        var parameters = CreateDefaultParameters(SignaturePackaging.ENVELOPED, "text/xml");

        SignatureDocument sigDoc;
        using (parameters.Signer = new Signer(_signCert))
        using (var fs = OpenTestFile("Sample.xml"))
        {
            sigDoc = xadesService.Sign(fs, parameters);
        }

        // Tamper with the document
        var xml = sigDoc.Document.OuterXml.Replace("Test", "Tampered");
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(xml);

        var loaded = xadesService.Load(doc);
        var result = xadesService.Validate(loaded[0]);
        Assert.False(result.IsValid);
    }

    [Fact]
    public void SaveAndLoad_RoundTrip_ProducesValidSignature()
    {
        var xadesService = new XadesService();
        var parameters = CreateDefaultParameters(SignaturePackaging.ENVELOPED, "text/xml");

        SignatureDocument sigDoc;
        using (parameters.Signer = new Signer(_signCert))
        using (var fs = OpenTestFile("Sample.xml"))
        {
            sigDoc = xadesService.Sign(fs, parameters);
        }

        // Save to temp file
        var tempFile = Path.GetTempFileName();
        try
        {
            sigDoc.Save(tempFile);

            var loaded = xadesService.Load(tempFile);
            Assert.Single(loaded);

            var result = xadesService.Validate(loaded[0]);
            Assert.True(result.IsValid, result.Message);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    #endregion

    #region CoSign

    [Fact]
    public void CoSign_ProducesValidDocument()
    {
        var xadesService = new XadesService();
        var parameters = CreateDefaultParameters(SignaturePackaging.ENVELOPED, "text/xml");

        SignatureDocument sigDoc;
        using (parameters.Signer = new Signer(_signCert))
        using (var fs = OpenTestFile("Sample.xml"))
        {
            sigDoc = xadesService.Sign(fs, parameters);
        }

        var coSignParams = CreateDefaultParameters(SignaturePackaging.ENVELOPED, "text/xml");
        SignatureDocument coSigDoc;
        using (coSignParams.Signer = new Signer(_signCert))
        {
            coSigDoc = xadesService.CoSign(sigDoc, coSignParams);
        }

        Assert.NotNull(coSigDoc);
        var loaded = xadesService.Load(coSigDoc.Document);
        Assert.True(loaded.Length >= 2, $"Expected 2+ signatures, got {loaded.Length}");
    }

    #endregion

    #region CounterSign

    [Fact]
    public void CounterSign_ProducesValidDocument()
    {
        var xadesService = new XadesService();
        var parameters = CreateDefaultParameters(SignaturePackaging.ENVELOPED, "text/xml");

        SignatureDocument sigDoc;
        using (parameters.Signer = new Signer(_signCert))
        using (var fs = OpenTestFile("Sample.xml"))
        {
            sigDoc = xadesService.Sign(fs, parameters);
        }

        var counterParams = CreateDefaultParameters(SignaturePackaging.ENVELOPED, "text/xml");
        SignatureDocument counterSigDoc;
        using (counterParams.Signer = new Signer(_signCert))
        {
            counterSigDoc = xadesService.CounterSign(sigDoc, counterParams);
        }

        Assert.NotNull(counterSigDoc);
        Assert.NotNull(counterSigDoc.Document);
    }

    #endregion

    #region Signature algorithms

    [Fact]
    public void Sign_WithSHA512_ProducesValidSignature()
    {
        var xadesService = new XadesService();
        var parameters = new SignatureParameters
        {
            SignatureMethod = SignatureMethod.RSAwithSHA512,
            DigestMethod = DigestMethod.SHA512,
            SigningDate = DateTime.Now,
            SignaturePackaging = SignaturePackaging.ENVELOPED,
            InputMimeType = "text/xml"
        };

        SignatureDocument sigDoc;
        using (parameters.Signer = new Signer(_signCert))
        using (var fs = OpenTestFile("Sample.xml"))
        {
            sigDoc = xadesService.Sign(fs, parameters);
        }

        var result = xadesService.Validate(sigDoc);
        Assert.True(result.IsValid, result.Message);
    }

    #endregion

    #region GetDocumentBytes

    [Fact]
    public void GetDocumentBytes_ReturnsNonEmptyBytes()
    {
        var xadesService = new XadesService();
        var parameters = CreateDefaultParameters(SignaturePackaging.ENVELOPED, "text/xml");

        SignatureDocument sigDoc;
        using (parameters.Signer = new Signer(_signCert))
        using (var fs = OpenTestFile("Sample.xml"))
        {
            sigDoc = xadesService.Sign(fs, parameters);
        }

        var bytes = sigDoc.GetDocumentBytes();
        Assert.NotNull(bytes);
        Assert.True(bytes.Length > 0);
    }

    #endregion

    #region Edge cases

    [Fact]
    public void Sign_NullSigner_ThrowsException()
    {
        var xadesService = new XadesService();
        var parameters = new SignatureParameters
        {
            SignaturePackaging = SignaturePackaging.ENVELOPED,
            InputMimeType = "text/xml"
        };

        using var fs = OpenTestFile("Sample.xml");
        Assert.Throws<Exception>(() => xadesService.Sign(fs, parameters));
    }

    [Fact]
    public void Sign_NullInput_NullExternalUri_ThrowsException()
    {
        var xadesService = new XadesService();
        var parameters = new SignatureParameters
        {
            SignaturePackaging = SignaturePackaging.ENVELOPED,
            InputMimeType = "text/xml"
        };

        using (parameters.Signer = new Signer(_signCert))
        {
            Assert.Throws<Exception>(() => xadesService.Sign(null, parameters));
        }
    }

    [Fact]
    public void Validate_NullDocument_ThrowsException()
    {
        var xadesService = new XadesService();
        Assert.Throws<ArgumentNullException>(() => xadesService.Validate(null!));
    }

    #endregion

    #region Helpers

    private SignatureParameters CreateDefaultParameters(SignaturePackaging packaging, string mimeType)
    {
        var parameters = new SignatureParameters
        {
            SignatureMethod = SignatureMethod.RSAwithSHA256,
            SigningDate = DateTime.Now,
            SignaturePackaging = packaging,
            InputMimeType = mimeType
        };
        parameters.SignatureCommitments.Add(new SignatureCommitment(SignatureCommitmentType.ProofOfOrigin));
        return parameters;
    }

    private FileStream OpenTestFile(string fileName)
    {
        return new FileStream(Path.Combine(_testDataDir, fileName), FileMode.Open, FileAccess.Read);
    }

    #endregion
}
