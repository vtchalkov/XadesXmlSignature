// --------------------------------------------------------------------------------------------------------------------
// XadesCUpgrader.cs
//
// FirmaXadesNet - Librería para la generación de firmas XADES
// Copyright (C) 2016 Dpto. de Nuevas Tecnologías de la Dirección General de Urbanismo del Ayto. de Cartagena
//
// This program is free software: you can redistribute it and/or modify
// it under the +terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
//
// --------------------------------------------------------------------------------------------------------------------

using FirmaXadesNet.Clients;
using FirmaXadesNet.Signature;
using FirmaXadesNet.Upgraders.Parameters;
using FirmaXadesNet.Utils;
using Microsoft.Xades;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using Org.BouncyCastle.X509.Store;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace FirmaXadesNet.Upgraders
{
    /// <summary>
    /// Upgrades a signature to XAdES-C by adding CompleteCertificateRefs and
    /// CompleteRevocationRefs (references only, no embedded values).
    /// </summary>
    class XadesCUpgrader : IXadesUpgrader
    {
        #region Public methods

        public void Upgrade(SignatureDocument signatureDocument, UpgradeParameters parameters)
        {
            UnsignedProperties unsignedProperties = signatureDocument.XadesSignature.UnsignedProperties;

            X509Certificate2 signingCertificate = signatureDocument.XadesSignature.GetSigningCertificate();

            unsignedProperties.UnsignedSignatureProperties.CompleteCertificateRefs = new CompleteCertificateRefs
            {
                Id = "CompleteCertificates-" + Guid.NewGuid().ToString()
            };

            unsignedProperties.UnsignedSignatureProperties.CompleteRevocationRefs = new CompleteRevocationRefs
            {
                Id = "CompleteRev-" + Guid.NewGuid().ToString()
            };

            AddCertificateRefs(signingCertificate, unsignedProperties, false, parameters.OCSPServers, parameters.CRL, parameters.DigestMethod, parameters.GetOcspUrlFromCertificate);

            AddTSACertificateRefs(unsignedProperties, parameters.OCSPServers, parameters.CRL, parameters.DigestMethod, parameters.GetOcspUrlFromCertificate);

            signatureDocument.XadesSignature.UnsignedProperties = unsignedProperties;

            signatureDocument.UpdateDocument();
        }

        #endregion

        #region Internal methods

        /// <summary>
        /// Adds certificate and revocation references for the given certificate and its chain.
        /// When addCert is true, the certificate reference is added to CompleteCertificateRefs.
        /// Revocation references (CRL or OCSP) are added to CompleteRevocationRefs.
        /// </summary>
        internal void AddCertificateRefs(X509Certificate2 cert, UnsignedProperties unsignedProperties, bool addCert,
            IEnumerable<OcspServer> ocspServers, IEnumerable<X509Crl> crlList, Crypto.DigestMethod digestMethod,
            bool addCertificateOcspUrl, X509Certificate2[] extraCerts = null, bool useNonce = true)
        {
            if (addCert)
            {
                if (CertificateRefExists(cert, unsignedProperties))
                {
                    return;
                }

                Cert chainCert = new Cert();
                chainCert.IssuerSerial.X509IssuerName = cert.IssuerName.Name;
                chainCert.IssuerSerial.X509SerialNumber = cert.GetSerialNumberAsDecimalString();
                DigestUtil.SetCertDigest(cert.GetRawCertData(), digestMethod, chainCert.CertDigest);
                unsignedProperties.UnsignedSignatureProperties.CompleteCertificateRefs.CertRefs.CertCollection.Add(chainCert);
            }

            var chain = CertUtil.GetCertChain(cert, extraCerts).ChainElements;

            if (chain.Count > 1)
            {
                X509ChainElementEnumerator enumerator = chain.GetEnumerator();
                enumerator.MoveNext(); // skip the certificate itself

                enumerator.MoveNext();

                bool valid = AddCRLRef(unsignedProperties, cert, enumerator.Current.Certificate, crlList, digestMethod);

                if (!valid)
                {
                    var ocspCerts = AddOCSPRef(unsignedProperties, cert, enumerator.Current.Certificate, ocspServers, digestMethod, addCertificateOcspUrl, useNonce);

                    if (ocspCerts != null)
                    {
                        X509Certificate2 startOcspCert = DetermineStartCert(ocspCerts);

                        if (!EquivalentDN(startOcspCert.IssuerName, enumerator.Current.Certificate.SubjectName))
                        {
                            var chainOcsp = CertUtil.GetCertChain(startOcspCert, ocspCerts);

                            AddCertificateRefs(chainOcsp.ChainElements[1].Certificate, unsignedProperties, true, ocspServers, crlList, digestMethod, addCertificateOcspUrl, ocspCerts);
                        }
                    }
                }

                AddCertificateRefs(enumerator.Current.Certificate, unsignedProperties, true, ocspServers, crlList, digestMethod, addCertificateOcspUrl, extraCerts);
            }
        }

        /// <summary>
        /// Adds certificate and revocation references for TSA certificates.
        /// </summary>
        internal void AddTSACertificateRefs(UnsignedProperties unsignedProperties, IEnumerable<OcspServer> ocspServers,
            IEnumerable<X509Crl> crlList, Crypto.DigestMethod digestMethod, bool addCertificateOcspUrl)
        {
            TimeStampToken token = new TimeStampToken(new CmsSignedData(unsignedProperties.UnsignedSignatureProperties.SignatureTimeStampCollection[0].EncapsulatedTimeStamp.PkiData));
            IX509Store store = token.GetCertificates("Collection");

            List<X509Certificate2> tsaCerts = new List<X509Certificate2>();
            foreach (var tsaCert in store.GetMatches(null))
            {
                X509Certificate2 cert = new X509Certificate2(((Org.BouncyCastle.X509.X509Certificate)tsaCert).GetEncoded());
                tsaCerts.Add(cert);
            }

            X509Certificate2 startCert = DetermineStartCert(tsaCerts.ToArray());
            AddCertificateRefs(startCert, unsignedProperties, true, ocspServers, crlList, digestMethod, addCertificateOcspUrl, tsaCerts.ToArray());
        }

        #endregion

        #region Private methods

        private string GetResponderName(ResponderID responderId, ref bool byKey)
        {
            DerTaggedObject dt = (DerTaggedObject)responderId.ToAsn1Object();

            if (dt.TagNo == 1)
            {
                byKey = false;
                return new X500DistinguishedName(dt.GetObject().GetEncoded()).Name;
            }
            else if (dt.TagNo == 2)
            {
                Asn1TaggedObject tagger = (Asn1TaggedObject)responderId.ToAsn1Object();
                Asn1OctetString pubInfo = (Asn1OctetString)tagger.GetObject();
                byKey = true;
                return Convert.ToBase64String(pubInfo.GetOctets());
            }
            else
            {
                return null;
            }
        }

        private bool EquivalentDN(X500DistinguishedName dn, X500DistinguishedName other)
        {
            return X509Name.GetInstance(Asn1Object.FromByteArray(dn.RawData)).Equivalent(X509Name.GetInstance(Asn1Object.FromByteArray(other.RawData)));
        }

        private bool CertificateRefExists(X509Certificate2 cert, UnsignedProperties unsignedProperties)
        {
            foreach (Cert item in unsignedProperties.UnsignedSignatureProperties.CompleteCertificateRefs.CertRefs.CertCollection)
            {
                if (item.IssuerSerial.X509IssuerName == cert.IssuerName.Name &&
                    item.IssuerSerial.X509SerialNumber == cert.GetSerialNumberAsDecimalString())
                {
                    return true;
                }
            }

            return false;
        }

        private bool ExistsCRL(CRLRefCollection collection, string issuer)
        {
            foreach (CRLRef crlRef in collection)
            {
                if (crlRef.CRLIdentifier.Issuer == issuer)
                {
                    return true;
                }
            }

            return false;
        }

        private long? GetCRLNumber(Org.BouncyCastle.X509.X509Crl crlEntry)
        {
            Asn1OctetString extValue = crlEntry.GetExtensionValue(X509Extensions.CrlNumber);

            if (extValue != null)
            {
                Asn1Object asn1Value = X509ExtensionUtilities.FromExtensionValue(extValue);
                return DerInteger.GetInstance(asn1Value).PositiveValue.LongValue;
            }

            return null;
        }

        /// <summary>
        /// Adds a CRL reference to CompleteRevocationRefs if the certificate is valid against the CRL.
        /// Returns true if a valid CRL was found.
        /// </summary>
        private bool AddCRLRef(UnsignedProperties unsignedProperties, X509Certificate2 certificate, X509Certificate2 issuer,
            IEnumerable<X509Crl> crlList, Crypto.DigestMethod digestMethod)
        {
            Org.BouncyCastle.X509.X509Certificate clientCert = certificate.ToBouncyX509Certificate();
            Org.BouncyCastle.X509.X509Certificate issuerCert = issuer.ToBouncyX509Certificate();

            foreach (var crlEntry in crlList)
            {
                if (crlEntry.IssuerDN.Equivalent(issuerCert.SubjectDN) && crlEntry.NextUpdate.Value > DateTime.Now)
                {
                    if (!crlEntry.IsRevoked(clientCert))
                    {
                        if (!ExistsCRL(unsignedProperties.UnsignedSignatureProperties.CompleteRevocationRefs.CRLRefs.CRLRefCollection,
                            issuer.Subject))
                        {
                            CRLRef crlRef = new CRLRef();
                            crlRef.CRLIdentifier.Issuer = issuer.Subject;
                            crlRef.CRLIdentifier.IssueTime = crlEntry.ThisUpdate.ToLocalTime();

                            var crlNumber = GetCRLNumber(crlEntry);
                            if (crlNumber.HasValue)
                            {
                                crlRef.CRLIdentifier.Number = crlNumber.Value;
                            }

                            byte[] crlEncoded = crlEntry.GetEncoded();
                            DigestUtil.SetCertDigest(crlEncoded, digestMethod, crlRef.CertDigest);

                            unsignedProperties.UnsignedSignatureProperties.CompleteRevocationRefs.CRLRefs.CRLRefCollection.Add(crlRef);
                        }

                        return true;
                    }
                    else
                    {
                        throw new Exception("Certificate revoked");
                    }
                }
            }

            return false;
        }

        /// <summary>
        /// Adds an OCSP reference to CompleteRevocationRefs if the certificate is valid via OCSP.
        /// Returns the OCSP responder certificates if successful.
        /// </summary>
        private X509Certificate2[] AddOCSPRef(UnsignedProperties unsignedProperties, X509Certificate2 client, X509Certificate2 issuer,
            IEnumerable<OcspServer> ocspServers, Crypto.DigestMethod digestMethod, bool addCertificateOcspUrl, bool useNonce)
        {
            bool byKey = false;
            List<OcspServer> finalOcspServers = new List<OcspServer>();
            Org.BouncyCastle.X509.X509Certificate clientCert = client.ToBouncyX509Certificate();
            Org.BouncyCastle.X509.X509Certificate issuerCert = issuer.ToBouncyX509Certificate();

            OcspClient ocsp = new OcspClient();

            if (addCertificateOcspUrl)
            {
                string certOcspUrl = ocsp.GetAuthorityInformationAccessOcspUrl(issuerCert);

                if (!string.IsNullOrEmpty(certOcspUrl))
                {
                    finalOcspServers.Add(new OcspServer(certOcspUrl));
                }
            }

            foreach (var ocspServer in ocspServers)
            {
                finalOcspServers.Add(ocspServer);
            }

            foreach (var ocspServer in finalOcspServers)
            {
                byte[] resp = ocsp.QueryBinary(clientCert, issuerCert, ocspServer.Url, useNonce, ocspServer.RequestorName,
                    ocspServer.SignCertificate);

                FirmaXadesNet.Clients.CertificateStatus status = ocsp.ProcessOcspResponse(resp, useNonce);

                if (status == FirmaXadesNet.Clients.CertificateStatus.Revoked)
                {
                    throw new Exception("Certificate revoked");
                }
                else if (status == FirmaXadesNet.Clients.CertificateStatus.Good)
                {
                    Org.BouncyCastle.Ocsp.OcspResp r = new OcspResp(resp);
                    byte[] rEncoded = r.GetEncoded();
                    BasicOcspResp or = (BasicOcspResp)r.GetResponseObject();

                    OCSPRef ocspRef = new OCSPRef();
                    DigestUtil.SetCertDigest(rEncoded, digestMethod, ocspRef.CertDigest);

                    ResponderID rpId = or.ResponderId.ToAsn1Object();
                    ocspRef.OCSPIdentifier.ResponderID = GetResponderName(rpId, ref byKey);
                    ocspRef.OCSPIdentifier.ByKey = byKey;

                    ocspRef.OCSPIdentifier.ProducedAt = or.ProducedAt.ToLocalTime();
                    unsignedProperties.UnsignedSignatureProperties.CompleteRevocationRefs.OCSPRefs.OCSPRefCollection.Add(ocspRef);

                    return (from cert in or.GetCerts()
                            select new X509Certificate2(cert.GetEncoded())).ToArray();
                }
            }

            throw new Exception("The certificate could not be validated");
        }

        private X509Certificate2 DetermineStartCert(X509Certificate2[] certs)
        {
            X509Certificate2 currentCert = null;
            bool isIssuer = true;

            for (int i = 0; i < certs.Length && isIssuer; i++)
            {
                currentCert = certs[i];
                isIssuer = false;

                for (int j = 0; j < certs.Length; j++)
                {
                    if (EquivalentDN(certs[j].IssuerName, currentCert.SubjectName))
                    {
                        isIssuer = true;
                        break;
                    }
                }
            }

            return currentCert;
        }

        #endregion
    }
}
