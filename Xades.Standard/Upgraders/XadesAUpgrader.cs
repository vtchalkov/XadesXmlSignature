// --------------------------------------------------------------------------------------------------------------------
// XadesAUpgrader.cs
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

using FirmaXadesNet.Signature;
using FirmaXadesNet.Upgraders.Parameters;
using FirmaXadesNet.Utils;
using Microsoft.Xades;
using System;
using System.Collections;
using System.Security.Cryptography.Xml;

namespace FirmaXadesNet.Upgraders
{
    /// <summary>
    /// Upgrades a signature to XAdES-A by adding an ArchiveTimeStamp element
    /// that covers the entire signature (including all unsigned properties).
    ///
    /// Per ETSI EN 319 132-1, the ArchiveTimeStamp covers:
    /// - SignedInfo
    /// - SignatureValue
    /// - KeyInfo
    /// - All SignedProperties and UnsignedProperties (including existing timestamps,
    ///   certificate values, revocation values, and any previous archive timestamps)
    ///
    /// This upgrader also supports archive timestamp renewal: calling Upgrade
    /// on a signature that already has ArchiveTimeStamp elements will add a new
    /// ArchiveTimeStamp that covers all previous ones, enabling long-term
    /// preservation as algorithms age.
    ///
    /// The ArchiveTimeStamp element uses the XAdES v1.4.1 namespace
    /// (http://uri.etsi.org/01903/v1.4.1#) as required by the standard.
    /// </summary>
    class XadesAUpgrader : IXadesUpgrader
    {
        #region Public methods

        public void Upgrade(SignatureDocument signatureDocument, UpgradeParameters parameters)
        {
            VerifyXLPresent(signatureDocument);

            AddArchiveTimeStamp(signatureDocument, parameters);

            signatureDocument.UpdateDocument();
        }

        #endregion

        #region Private methods

        private void VerifyXLPresent(SignatureDocument signatureDocument)
        {
            var unsignedProps = signatureDocument.XadesSignature.UnsignedProperties.UnsignedSignatureProperties;

            if (unsignedProps.SignatureTimeStampCollection.Count == 0)
            {
                throw new Exception("SignatureTimeStamp is required for XAdES-A upgrade. Upgrade to XAdES-T first.");
            }

            if (unsignedProps.CompleteCertificateRefs == null || !unsignedProps.CompleteCertificateRefs.HasChanged())
            {
                throw new Exception("CompleteCertificateRefs is required for XAdES-A upgrade. Upgrade to XAdES-XL first.");
            }

            if (unsignedProps.CertificateValues == null || !unsignedProps.CertificateValues.HasChanged())
            {
                throw new Exception("CertificateValues is required for XAdES-A upgrade. Upgrade to XAdES-XL first.");
            }
        }

        /// <summary>
        /// Computes a hash over all elements that the ArchiveTimeStamp must cover
        /// and requests a timestamp from the TSA.
        ///
        /// Per ETSI TS 101 903 V1.4.1 §7.7, the input to the archive timestamp is
        /// the concatenation of the canonicalized forms of:
        /// 1. SignatureValue
        /// 2. SignatureTimeStamp (all)
        /// 3. CompleteCertificateRefs
        /// 4. CompleteRevocationRefs
        /// 5. CertificateValues
        /// 6. RevocationValues
        /// 7. SigAndRefsTimeStamp or RefsOnlyTimeStamp (all)
        /// 8. All previous ArchiveTimeStamp elements
        ///
        /// Additionally, SignedInfo, KeyInfo, and SignedProperties are covered
        /// through the ds:Reference mechanism.
        /// </summary>
        private void AddArchiveTimeStamp(SignatureDocument signatureDocument, UpgradeParameters parameters)
        {
            // Ensure the document is up-to-date before computing hashes
            signatureDocument.UpdateDocument();

            // Build the list of XPaths covering all elements for the archive timestamp.
            // Per the XAdES specification, the archive timestamp input includes
            // the signature value and all unsigned signature properties added by
            // previous levels (T, C, X, XL) plus any existing archive timestamps.
            ArrayList archiveElementXpaths = new ArrayList
            {
                "ds:SignatureValue"
            };

            // Add SignedInfo and KeyInfo to ensure complete coverage
            archiveElementXpaths.Add("ds:SignedInfo");
            archiveElementXpaths.Add("ds:KeyInfo");

            // SignedProperties
            archiveElementXpaths.Add("ds:Object/xades:QualifyingProperties/xades:SignedProperties");

            // All unsigned properties from T, C, X, XL levels
            string unsignedBasePath = "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties";

            archiveElementXpaths.Add(unsignedBasePath + "/xades:SignatureTimeStamp");
            archiveElementXpaths.Add(unsignedBasePath + "/xades:CompleteCertificateRefs");
            archiveElementXpaths.Add(unsignedBasePath + "/xades:CompleteRevocationRefs");
            archiveElementXpaths.Add(unsignedBasePath + "/xades:CertificateValues");
            archiveElementXpaths.Add(unsignedBasePath + "/xades:RevocationValues");

            // Include SigAndRefsTimeStamp or RefsOnlyTimeStamp if present
            AddXPathIfElementExists(signatureDocument, archiveElementXpaths, unsignedBasePath + "/xades:SigAndRefsTimeStamp");
            AddXPathIfElementExists(signatureDocument, archiveElementXpaths, unsignedBasePath + "/xades:RefsOnlyTimeStamp");

            // Include any existing ArchiveTimeStamp elements (for renewal)
            AddArchiveTimeStampXPaths(signatureDocument, archiveElementXpaths, unsignedBasePath);

            byte[] archiveHash = DigestUtil.ComputeHashValue(
                XMLUtil.ComputeValueOfElementList(signatureDocument.XadesSignature, archiveElementXpaths),
                parameters.DigestMethod);

            byte[] tsa = parameters.TimeStampClient.GetTimeStamp(archiveHash, parameters.DigestMethod, true);

            // Create the ArchiveTimeStamp using the XAdES v1.4.1 namespace
            TimeStamp archiveTimeStamp = new TimeStamp("ArchiveTimeStamp", "xadesv141", XadesSignedXml.XadesNamespace141Uri)
            {
                Id = "ArchiveTimeStamp-" + Guid.NewGuid().ToString()
            };
            archiveTimeStamp.EncapsulatedTimeStamp.PkiData = tsa;
            archiveTimeStamp.EncapsulatedTimeStamp.Id = "ArchiveTimeStamp-" + Guid.NewGuid().ToString();

            UnsignedProperties unsignedProperties = signatureDocument.XadesSignature.UnsignedProperties;
            unsignedProperties.UnsignedSignatureProperties.ArchiveTimeStampCollection.Add(archiveTimeStamp);

            signatureDocument.XadesSignature.UnsignedProperties = unsignedProperties;
        }

        /// <summary>
        /// Adds the XPath to the list only if the element actually exists in the document.
        /// This prevents errors when computing hash values for elements that may not be present.
        /// </summary>
        private void AddXPathIfElementExists(SignatureDocument signatureDocument, ArrayList xpaths, string xpath)
        {
            var signatureXmlElement = signatureDocument.XadesSignature.GetSignatureElement();
            var xmlNamespaceManager = new System.Xml.XmlNamespaceManager(signatureDocument.Document.NameTable);
            xmlNamespaceManager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
            xmlNamespaceManager.AddNamespace("xades", XadesSignedXml.XadesNamespaceUri);

            var nodes = signatureXmlElement.SelectNodes(xpath, xmlNamespaceManager);
            if (nodes != null && nodes.Count > 0)
            {
                xpaths.Add(xpath);
            }
        }

        /// <summary>
        /// Adds XPaths for any existing ArchiveTimeStamp elements.
        /// These may be in either the xades or xadesv141 namespace.
        /// </summary>
        private void AddArchiveTimeStampXPaths(SignatureDocument signatureDocument, ArrayList xpaths, string unsignedBasePath)
        {
            var signatureXmlElement = signatureDocument.XadesSignature.GetSignatureElement();
            var xmlNamespaceManager = new System.Xml.XmlNamespaceManager(signatureDocument.Document.NameTable);
            xmlNamespaceManager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
            xmlNamespaceManager.AddNamespace("xades", XadesSignedXml.XadesNamespaceUri);
            xmlNamespaceManager.AddNamespace("xadesv141", XadesSignedXml.XadesNamespace141Uri);

            // Check for ArchiveTimeStamp in the xades namespace (legacy)
            string xadesArchivePath = unsignedBasePath + "/xades:ArchiveTimeStamp";
            var xadesNodes = signatureXmlElement.SelectNodes(xadesArchivePath, xmlNamespaceManager);
            if (xadesNodes != null && xadesNodes.Count > 0)
            {
                xpaths.Add(xadesArchivePath);
            }

            // Check for ArchiveTimeStamp in the xadesv141 namespace
            string xades141ArchivePath = unsignedBasePath + "/xadesv141:ArchiveTimeStamp";
            var xades141Nodes = signatureXmlElement.SelectNodes(xades141ArchivePath, xmlNamespaceManager);
            if (xades141Nodes != null && xades141Nodes.Count > 0)
            {
                xpaths.Add(xades141ArchivePath);
            }
        }

        #endregion
    }
}
