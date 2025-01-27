using FirmaXadesNet;
using FirmaXadesNet.Clients;
using FirmaXadesNet.Crypto;
using FirmaXadesNet.Signature.Parameters;
using FirmaXadesNet.Upgraders;
using FirmaXadesNet.Upgraders.Parameters;
using FirmaXadesNet.Utils;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using Xunit;
using Xunit.Sdk;

namespace Tests
{
    public class Xades
    {
        readonly X509Certificate2 _signCertificate;
        readonly AsymmetricKeyParameter _caPrivKey;
        readonly X509Certificate2 _rootCert;
        readonly string rootDirectory;
        public Xades()
        {
            _caPrivKey = GenerateCACertificate("CN=root ca", out _rootCert);
            _signCertificate = GenerateSelfSignedCertificate("CN=127.0.0.1", "CN=root ca", _caPrivKey);
            //To get the location the assembly normally resides on disk or the install directory
            var rootPath = System.Reflection.Assembly.GetExecutingAssembly().CodeBase;
            //once you have the path you get the directory with:
            rootDirectory = System.IO.Path.GetDirectoryName(new Uri(rootPath).LocalPath);
        }
        [Theory]
        [Repeat(1)]
        public void SimpleXadesTSign(object input)
        {
            Console.WriteLine(input.ToString());
            Assert.True(CertUtil.VerifyCertificate(_signCertificate, _rootCert, X509RevocationMode.NoCheck));
            using (var inputStream = System.IO.File.OpenRead(Path.Combine(rootDirectory, @"Sample.xml")))
            {
                var result = SignDocument(_signCertificate, inputStream, new SignatureProductionPlace
                {
                    City = "Sofia",
                    CountryName = "Bulgaria",
                    PostalCode = "1303",
                    StateOrProvince = "Sofia"
                }, "http://timestamp.comodoca.com/rfc3161");
                ValidateDocument(result);
                ValidateDocumentSignatureOnly(result);
            }
        }

        [Fact]
        public void SimpleXadesTSignWithFile()
        {
            X509Store my = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            my.Open(OpenFlags.ReadOnly);
            var signCertificate = my.Certificates.Find(X509FindType.FindBySerialNumber, "3600000024614590f115537e5f000000000024", true)[0];
            var rootCertificate = my.Certificates.Find(X509FindType.FindBySerialNumber, "13d930c77129a28949871e02de5a2aab", true)[0];

            Assert.True(CertUtil.VerifyCertificate(signCertificate, rootCertificate, X509RevocationMode.NoCheck));
            using (var inputStream = System.IO.File.OpenRead(Path.Combine(rootDirectory, @"SampleWithFile.xml")))
            {
                var result = SignDocument(signCertificate, inputStream, new SignatureProductionPlace
                {
                    City = "Sofia",
                    CountryName = "Bulgaria",
                    PostalCode = "1303",
                    StateOrProvince = "Sofia"
                }, "http://timestamp.comodoca.com/rfc3161");
                System.IO.File.WriteAllText(@"c:\temp\xades-t.xml", result);
                ValidateDocument(result);
                ValidateDocumentSignatureOnly(result);
            }
        }

        [Fact]
        public void SimpleXadesXLSignWithFile()
        {
            X509Store my = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            my.Open(OpenFlags.ReadOnly);
            var signCertificate = my.Certificates.Find(X509FindType.FindBySerialNumber, "3600000024614590f115537e5f000000000024", true)[0];
            var rootCertificate = my.Certificates.Find(X509FindType.FindBySerialNumber, "13d930c77129a28949871e02de5a2aab", true)[0];

            Assert.True(CertUtil.VerifyCertificate(signCertificate, rootCertificate, X509RevocationMode.NoCheck));
            using (var inputStream = System.IO.File.OpenRead(Path.Combine(rootDirectory, @"SampleWithFile.xml")))
            {
                var result = SignDocument(signCertificate, inputStream, new SignatureProductionPlace
                {
                    City = "Sofia",
                    CountryName = "Bulgaria",
                    PostalCode = "1303",
                    StateOrProvince = "Sofia"
                }, "https://freetsa.org/tsr", SignatureFormat.XAdES_XL);
                System.IO.File.WriteAllText(@"c:\temp\xades-xl.xml", result);
                ValidateDocument(result);
                ValidateDocumentSignatureOnly(result);
            }
            my.Close();
        }

        [Fact]
        public void RunInternallyDetachedSignature()
        {
            FirmaXadesNet.XadesService xadesService = new XadesService();
            SignatureParameters parametros = new SignatureParameters();

            string ficheroXml = Path.Combine(rootDirectory, @"xsdBOE-A-2011-13169_ex_XAdES_Internally_detached.xml");

            XmlDocument documento = new XmlDocument();
            documento.Load(ficheroXml);

            parametros.SignatureDestination = new SignatureXPathExpression();
            parametros.SignatureDestination.Namespaces.Add("enidoc", "http://administracionelectronica.gob.es/ENI/XSD/v1.0/documento-e");
            parametros.SignatureDestination.Namespaces.Add("enidocmeta", "http://administracionelectronica.gob.es/ENI/XSD/v1.0/documento-e/metadatos");
            parametros.SignatureDestination.Namespaces.Add("enids", "http://administracionelectronica.gob.es/ENI/XSD/v1.0/firma");
            parametros.SignatureDestination.Namespaces.Add("enifile", "http://administracionelectronica.gob.es/ENI/XSD/v1.0/documento-e/contenido");
            parametros.SignatureDestination.XPathExpression = "enidoc:documento/enids:firmas/enids:firma/enids:ContenidoFirma/enids:FirmaConCertificado";
            parametros.SignaturePackaging = SignaturePackaging.INTERNALLY_DETACHED;
            parametros.ElementIdToSign = "CONTENT-12ef114d-ac6c-4da3-8caf-50379ed13698";
            parametros.InputMimeType = "text/xml";

            FirmaXadesNet.Signature.SignatureDocument documentoFirma;

            using (parametros.Signer = new Signer(_signCertificate))
            {
                using (FileStream fs = new FileStream(ficheroXml, FileMode.Open))
                {
                    documentoFirma = xadesService.Sign(fs, parametros);
                }
            }

            ValidateDocument(documentoFirma.Document.OuterXml);

        }

        [Fact]
        public void RunInvoiceSignature()
        {
            XadesService xadesService = new XadesService();
            SignatureParameters parametros = new SignatureParameters();

            string ficheroFactura = Path.Combine(rootDirectory, @"Facturae.xml");

            // Política de firma de factura-e 3.1
            parametros.SignaturePolicyInfo = new SignaturePolicyInfo
            {
                PolicyIdentifier = "http://www.facturae.es/politica_de_firma_formato_facturae/politica_de_firma_formato_facturae_v3_1.pdf",
                PolicyHash = "Ohixl6upD6av8N7pEvDABhEL6hM="
            };
            parametros.SignaturePackaging = SignaturePackaging.ENVELOPED;
            parametros.InputMimeType = "text/xml";
            parametros.SignerRole = new SignerRole();
            parametros.SignerRole.ClaimedRoles.Add("emisor");

            using (parametros.Signer = new Signer(_signCertificate))
            {
                using (FileStream fs = new FileStream(ficheroFactura, FileMode.Open))
                {
                    var docFirmado = xadesService.Sign(fs, parametros);
                    ValidateDocument(docFirmado.Document.OuterXml);
                }
            }
        }

        string SignDocument(X509Certificate2 signCertificate, System.IO.Stream inputStream, SignatureProductionPlace signatureProductionPlace, string timeStampUrl = "https://freetsa.org/tsr", SignatureFormat format = SignatureFormat.XAdES_T)
        {
            FirmaXadesNet.XadesService svc = new FirmaXadesNet.XadesService();

            var parameters = new SignatureParameters()
            {
                SignatureMethod = SignatureMethod.RSAwithSHA256,
                SigningDate = DateTime.Now,
                SignaturePackaging = SignaturePackaging.ENVELOPED,
                InputMimeType = "text/xml",
                SignatureProductionPlace = signatureProductionPlace
            };
            parameters.SignatureCommitments.Add(new SignatureCommitment(SignatureCommitmentType.ProofOfOrigin));

            using (parameters.Signer = new Signer(signCertificate))
            {
                var signedDocument = svc.Sign(inputStream, parameters);
                signedDocument.Document.PreserveWhitespace = true;
                UpgradeParameters xadesTparameters = new UpgradeParameters()
                {
                    TimeStampClient = new TimeStampClient(timeStampUrl)
                };
                if (format == SignatureFormat.XAdES_XL)
                {
                    xadesTparameters.OCSPServers.Add(new OcspServer("http://srvdc06.crossroad.ltd/ocsp"));
                }
                XadesUpgraderService upgrader = new XadesUpgraderService();
                upgrader.Upgrade(signedDocument, format, xadesTparameters);

                return signedDocument.Document.OuterXml;

            }

        }

        void ValidateDocument(string xml)
        {
            FirmaXadesNet.XadesService svc = new FirmaXadesNet.XadesService();
            XmlDocument doc = new XmlDocument
            {
                PreserveWhitespace = true
            };
            doc.LoadXml(xml);
            var resultDoc = svc.Load(doc);

            var result2 = svc.Validate(resultDoc[0]);
            Assert.True(result2.IsValid);
        }
        void ValidateDocumentSignatureOnly(string xml)
        {
            //signedDocument.Save(@"c:\temp\xades.xml");
            FirmaXadesNet.XadesService svc = new FirmaXadesNet.XadesService();
            XmlDocument doc = new XmlDocument
            {
                PreserveWhitespace = true
            };
            doc.LoadXml(xml);
            var resultDoc = svc.Load(doc);

            var result = resultDoc[0].XadesSignature.XadesCheckSignature(Microsoft.Xades.XadesCheckSignatureMasks.AllChecks);
            Assert.True(result);

        }
        X509Certificate2 GenerateSelfSignedCertificate(string subjectName, string issuerName, AsymmetricKeyParameter issuerPrivKey, int keyStrength = 2048)
        {
            // Generating Random Numbers
            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);

            // The Certificate Generator
            var certificateGenerator = new X509V3CertificateGenerator();

            // Serial Number
            var serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), random);
            certificateGenerator.SetSerialNumber(serialNumber);

            // Signature Algorithm
            const string signatureAlgorithm = "SHA256WithRSA";

            // Issuer and Subject Name
            var subjectDN = new X509Name(subjectName);
            var issuerDN = new X509Name(issuerName);
            certificateGenerator.SetIssuerDN(issuerDN);
            certificateGenerator.SetSubjectDN(subjectDN);

            // Valid For
            var notBefore = DateTime.UtcNow.Date;
            var notAfter = notBefore.AddYears(2);

            certificateGenerator.SetNotBefore(notBefore);
            certificateGenerator.SetNotAfter(notAfter);


            // Subject Public Key
            AsymmetricCipherKeyPair subjectKeyPair;
            var keyGenerationParameters = new KeyGenerationParameters(random, keyStrength);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            subjectKeyPair = keyPairGenerator.GenerateKeyPair();

            certificateGenerator.SetPublicKey(subjectKeyPair.Public);

            // Generating the Certificate
            var issuerKeyPair = subjectKeyPair;

            // create key factory
            ISignatureFactory signatureFactory = new Asn1SignatureFactory(signatureAlgorithm, issuerPrivKey, random);

            // selfsign certificate
            var certificate = certificateGenerator.Generate(signatureFactory);

            // correcponding private key
            PrivateKeyInfo info = PrivateKeyInfoFactory.CreatePrivateKeyInfo(subjectKeyPair.Private);

            // merge into X509Certificate2
            var x509 = new System.Security.Cryptography.X509Certificates.X509Certificate2(certificate.GetEncoded());

            var seq = (Asn1Sequence)Asn1Object.FromByteArray(info.ParsePrivateKey().GetDerEncoded());
            if (seq.Count != 9)
                throw new PemException("malformed sequence in RSA private key");

            var rsa = RsaPrivateKeyStructure.GetInstance(seq);
            RsaPrivateCrtKeyParameters rsaparams = new RsaPrivateCrtKeyParameters(
                rsa.Modulus, rsa.PublicExponent, rsa.PrivateExponent, rsa.Prime1, rsa.Prime2, rsa.Exponent1, rsa.Exponent2, rsa.Coefficient);

            x509.PrivateKey = DotNetUtilities.ToRSA(rsaparams);
            return x509;
        }


        AsymmetricKeyParameter GenerateCACertificate(string subjectName, out X509Certificate2 rootCertificate, int keyStrength = 2048)
        {
            // Generating Random Numbers
            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);

            // The Certificate Generator
            var certificateGenerator = new X509V3CertificateGenerator();

            // Serial Number
            var serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), random);
            certificateGenerator.SetSerialNumber(serialNumber);

            // Signature Algorithm
            const string signatureAlgorithm = "SHA256WithRSA";

            // Issuer and Subject Name
            var subjectDN = new X509Name(subjectName);
            var issuerDN = subjectDN;
            certificateGenerator.SetIssuerDN(issuerDN);
            certificateGenerator.SetSubjectDN(subjectDN);

            // Valid For
            var notBefore = DateTime.UtcNow.Date;
            var notAfter = notBefore.AddYears(2);

            certificateGenerator.SetNotBefore(notBefore);
            certificateGenerator.SetNotAfter(notAfter);

            // Subject Public Key
            AsymmetricCipherKeyPair subjectKeyPair;
            var keyGenerationParameters = new KeyGenerationParameters(random, keyStrength);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            subjectKeyPair = keyPairGenerator.GenerateKeyPair();

            certificateGenerator.SetPublicKey(subjectKeyPair.Public);

            // Generating the Certificate
            var issuerKeyPair = subjectKeyPair;

            // create key factory
            ISignatureFactory signatureFactory = new Asn1SignatureFactory(signatureAlgorithm, issuerKeyPair.Private, random);

            // selfsign certificate
            var certificate = certificateGenerator.Generate(signatureFactory);
            rootCertificate = new System.Security.Cryptography.X509Certificates.X509Certificate2(certificate.GetEncoded());
            return issuerKeyPair.Private;
        }
    }

    public sealed class RepeatAttribute : DataAttribute
    {
        private readonly int _count;

        public RepeatAttribute(int count)
        {
            if (count < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(count),
                      "Repeat count must be greater than 0.");
            }
            _count = count;
        }

        public override IEnumerable<object[]> GetData(MethodInfo testMethod)
        {
            return Enumerable.Range(0, _count).Select(item => new object[] { (object)item });
        }
    }
}