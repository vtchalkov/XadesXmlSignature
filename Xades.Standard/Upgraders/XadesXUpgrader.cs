// --------------------------------------------------------------------------------------------------------------------
// XadesXUpgrader.cs
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
using System.Xml;

namespace FirmaXadesNet.Upgraders
{
    /// <summary>
    /// Upgrades a signature to XAdES-X by adding a SigAndRefsTimeStamp or
    /// RefsOnlyTimeStamp over the signature value and references.
    /// Requires that CompleteCertificateRefs and CompleteRevocationRefs are
    /// already present (i.e., the signature must be at least XAdES-C level).
    /// </summary>
    class XadesXUpgrader : IXadesUpgrader
    {
        #region Public methods

        public void Upgrade(SignatureDocument signatureDocument, UpgradeParameters parameters)
        {
            VerifyCompletionRefsPresent(signatureDocument);

            if (parameters.RefsOnlyTimeStamp)
            {
                AddRefsOnlyTimeStamp(signatureDocument, parameters);
            }
            else
            {
                AddSigAndRefsTimeStamp(signatureDocument, parameters);
            }

            signatureDocument.UpdateDocument();
        }

        #endregion

        #region Internal methods

        /// <summary>
        /// Adds a SigAndRefsTimeStamp to the signature. Can be called externally
        /// by XadesXLUpgrader to compose the XL upgrade.
        /// </summary>
        internal void AddSigAndRefsTimeStamp(SignatureDocument signatureDocument, UpgradeParameters parameters)
        {
            XmlElement nodoFirma = signatureDocument.XadesSignature.GetSignatureElement();

            XmlNamespaceManager nm = new XmlNamespaceManager(signatureDocument.Document.NameTable);
            nm.AddNamespace("xades", XadesSignedXml.XadesNamespaceUri);
            nm.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);

            XmlNode xmlCompleteCertRefs = nodoFirma.SelectSingleNode("ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:CompleteCertificateRefs", nm);

            if (xmlCompleteCertRefs == null)
            {
                signatureDocument.UpdateDocument();
            }

            ArrayList signatureValueElementXpaths = new ArrayList
            {
                "ds:SignatureValue",
                "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:SignatureTimeStamp",
                "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:CompleteCertificateRefs",
                "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:CompleteRevocationRefs"
            };
            byte[] signatureValueHash = DigestUtil.ComputeHashValue(XMLUtil.ComputeValueOfElementList(signatureDocument.XadesSignature, signatureValueElementXpaths), parameters.DigestMethod);

            byte[] tsa = parameters.TimeStampClient.GetTimeStamp(signatureValueHash, parameters.DigestMethod, true);

            TimeStamp xadesXTimeStamp = new TimeStamp("SigAndRefsTimeStamp")
            {
                Id = "SigAndRefsStamp-" + signatureDocument.XadesSignature.Signature.Id
            };
            xadesXTimeStamp.EncapsulatedTimeStamp.PkiData = tsa;
            xadesXTimeStamp.EncapsulatedTimeStamp.Id = "SigAndRefsStamp-" + Guid.NewGuid().ToString();

            UnsignedProperties unsignedProperties = signatureDocument.XadesSignature.UnsignedProperties;
            unsignedProperties.UnsignedSignatureProperties.RefsOnlyTimeStampFlag = false;
            unsignedProperties.UnsignedSignatureProperties.SigAndRefsTimeStampCollection.Add(xadesXTimeStamp);

            signatureDocument.XadesSignature.UnsignedProperties = unsignedProperties;
        }

        #endregion

        #region Private methods

        private void VerifyCompletionRefsPresent(SignatureDocument signatureDocument)
        {
            var unsignedProps = signatureDocument.XadesSignature.UnsignedProperties.UnsignedSignatureProperties;

            if (unsignedProps.CompleteCertificateRefs == null || !unsignedProps.CompleteCertificateRefs.HasChanged())
            {
                throw new Exception("CompleteCertificateRefs is required for XAdES-X upgrade. Upgrade to XAdES-C first.");
            }

            if (unsignedProps.CompleteRevocationRefs == null || !unsignedProps.CompleteRevocationRefs.HasChanged())
            {
                throw new Exception("CompleteRevocationRefs is required for XAdES-X upgrade. Upgrade to XAdES-C first.");
            }
        }

        private void AddRefsOnlyTimeStamp(SignatureDocument signatureDocument, UpgradeParameters parameters)
        {
            XmlElement nodoFirma = signatureDocument.XadesSignature.GetSignatureElement();

            XmlNamespaceManager nm = new XmlNamespaceManager(signatureDocument.Document.NameTable);
            nm.AddNamespace("xades", XadesSignedXml.XadesNamespaceUri);
            nm.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);

            XmlNode xmlCompleteCertRefs = nodoFirma.SelectSingleNode("ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:CompleteCertificateRefs", nm);

            if (xmlCompleteCertRefs == null)
            {
                signatureDocument.UpdateDocument();
            }

            // RefsOnlyTimeStamp covers only the references, not SignatureValue
            ArrayList refsOnlyElementXpaths = new ArrayList
            {
                "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:CompleteCertificateRefs",
                "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:CompleteRevocationRefs"
            };
            byte[] refsHash = DigestUtil.ComputeHashValue(XMLUtil.ComputeValueOfElementList(signatureDocument.XadesSignature, refsOnlyElementXpaths), parameters.DigestMethod);

            byte[] tsa = parameters.TimeStampClient.GetTimeStamp(refsHash, parameters.DigestMethod, true);

            TimeStamp refsOnlyTimeStamp = new TimeStamp("RefsOnlyTimeStamp")
            {
                Id = "RefsOnlyStamp-" + signatureDocument.XadesSignature.Signature.Id
            };
            refsOnlyTimeStamp.EncapsulatedTimeStamp.PkiData = tsa;
            refsOnlyTimeStamp.EncapsulatedTimeStamp.Id = "RefsOnlyStamp-" + Guid.NewGuid().ToString();

            UnsignedProperties unsignedProperties = signatureDocument.XadesSignature.UnsignedProperties;
            unsignedProperties.UnsignedSignatureProperties.RefsOnlyTimeStampFlag = true;
            unsignedProperties.UnsignedSignatureProperties.RefsOnlyTimeStampCollection.Add(refsOnlyTimeStamp);

            signatureDocument.XadesSignature.UnsignedProperties = unsignedProperties;
        }

        #endregion
    }
}
