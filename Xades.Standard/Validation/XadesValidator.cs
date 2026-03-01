// --------------------------------------------------------------------------------------------------------------------
// XadesValidator.cs
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
// E-Mail: informatica@gemuc.es
//
// --------------------------------------------------------------------------------------------------------------------


using FirmaXadesNet.Signature;
using FirmaXadesNet.Utils;
using Microsoft.Xades;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.Utilities;
using System.Collections;

namespace FirmaXadesNet.Validation
{
    class XadesValidator
    {
        #region Public methods

        /// <summary>
        /// Validates a XAdES signature at all present levels:
        /// 1. The digests of the references of the signature (XAdES-B).
        /// 2. The digest of SignedInfo is verified and the signature is verified
        ///    with the public key of the certificate (XAdES-B).
        /// 3. If the signature contains a SignatureTimeStamp, verify that the
        ///    imprint matches the SignatureValue hash (XAdES-T).
        /// 4. If CompleteCertificateRefs are present, verify their consistency
        ///    with CertificateValues when available (XAdES-C).
        /// 5. If SigAndRefsTimeStamp or RefsOnlyTimeStamp are present, verify
        ///    the timestamp covers the correct elements (XAdES-X).
        /// 6. If CertificateValues and RevocationValues are present, verify
        ///    consistency with references (XAdES-XL).
        /// 7. If ArchiveTimeStamp elements are present, verify the timestamp
        ///    tokens are structurally valid (XAdES-A).
        /// </summary>
        /// <param name="sigDocument"></param>
        /// <returns></returns>
        public ValidationResult Validate(SignatureDocument sigDocument)
        {
            ValidationResult result = new ValidationResult();

            try
            {
                // Check the traces of references and signature
                sigDocument.XadesSignature.CheckXmldsigSignature();
            }
            catch
            {
                result.IsValid = false;
                result.Message = "Signature verification is unsuccessful!";

                return result;
            }

            // Validate XAdES-T: SignatureTimeStamp
            if (sigDocument.XadesSignature.UnsignedProperties.UnsignedSignatureProperties.SignatureTimeStampCollection.Count > 0)
            {
                var tsResult = ValidateSignatureTimeStamp(sigDocument);
                if (!tsResult.IsValid)
                {
                    return tsResult;
                }
            }

            var unsignedProps = sigDocument.XadesSignature.UnsignedProperties.UnsignedSignatureProperties;

            // Validate XAdES-C: CompleteCertificateRefs
            if (unsignedProps.CompleteCertificateRefs != null && unsignedProps.CompleteCertificateRefs.HasChanged())
            {
                var cResult = ValidateCompleteCertificateRefs(sigDocument);
                if (!cResult.IsValid)
                {
                    return cResult;
                }
            }

            // Validate XAdES-X: SigAndRefsTimeStamp or RefsOnlyTimeStamp
            if (unsignedProps.SigAndRefsTimeStampCollection.Count > 0)
            {
                var xResult = ValidateSigAndRefsTimeStamp(sigDocument);
                if (!xResult.IsValid)
                {
                    return xResult;
                }
            }
            else if (unsignedProps.RefsOnlyTimeStampCollection.Count > 0)
            {
                var xResult = ValidateRefsOnlyTimeStamp(sigDocument);
                if (!xResult.IsValid)
                {
                    return xResult;
                }
            }

            // Validate XAdES-XL: CertificateValues and RevocationValues
            if (unsignedProps.CertificateValues != null && unsignedProps.CertificateValues.HasChanged())
            {
                var xlResult = ValidateCertificateValues(sigDocument);
                if (!xlResult.IsValid)
                {
                    return xlResult;
                }
            }

            // Validate XAdES-A: ArchiveTimeStamp
            if (unsignedProps.ArchiveTimeStampCollection.Count > 0)
            {
                var aResult = ValidateArchiveTimeStamps(sigDocument);
                if (!aResult.IsValid)
                {
                    return aResult;
                }
            }

            result.IsValid = true;
            result.Message = "Signature validated successfully";

            return result;
        }

        #endregion

        #region Private methods

        /// <summary>
        /// Validates the SignatureTimeStamp (XAdES-T level).
        /// Verifies that the timestamp's message imprint matches the hash
        /// of the SignatureValue element.
        /// </summary>
        private ValidationResult ValidateSignatureTimeStamp(SignatureDocument sigDocument)
        {
            var result = new ValidationResult();

            TimeStamp timeStamp = sigDocument.XadesSignature.UnsignedProperties.UnsignedSignatureProperties.SignatureTimeStampCollection[0];
            TimeStampToken token = new TimeStampToken(new CmsSignedData(timeStamp.EncapsulatedTimeStamp.PkiData));

            byte[] tsHashValue = token.TimeStampInfo.GetMessageImprintDigest();
            Crypto.DigestMethod tsDigestMethod = Crypto.DigestMethod.GetByOid(token.TimeStampInfo.HashAlgorithm.Algorithm.Id);

            ArrayList signatureValueElementXpaths = new ArrayList
            {
                "ds:SignatureValue"
            };
            byte[] signatureValueHash = DigestUtil.ComputeHashValue(XMLUtil.ComputeValueOfElementList(sigDocument.XadesSignature, signatureValueElementXpaths), tsDigestMethod);

            if (!Arrays.AreEqual(tsHashValue, signatureValueHash))
            {
                result.IsValid = false;
                result.Message = "The imprint of the time stamp does not correspond with the calculated";
                return result;
            }

            result.IsValid = true;
            return result;
        }

        /// <summary>
        /// Validates CompleteCertificateRefs (XAdES-C level).
        /// Verifies that certificate references are present and, when
        /// CertificateValues are also available, that each reference's digest
        /// matches an embedded certificate.
        /// </summary>
        private ValidationResult ValidateCompleteCertificateRefs(SignatureDocument sigDocument)
        {
            var result = new ValidationResult { IsValid = true };
            var unsignedProps = sigDocument.XadesSignature.UnsignedProperties.UnsignedSignatureProperties;
            var certRefs = unsignedProps.CompleteCertificateRefs;

            if (certRefs.CertRefs.CertCollection.Count == 0)
            {
                result.IsValid = false;
                result.Message = "CompleteCertificateRefs is present but contains no certificate references";
                return result;
            }

            // If CertificateValues are present, verify cross-references
            if (unsignedProps.CertificateValues != null && unsignedProps.CertificateValues.HasChanged())
            {
                foreach (Cert certRef in certRefs.CertRefs.CertCollection)
                {
                    if (certRef.CertDigest.DigestValue == null || certRef.CertDigest.DigestValue.Length == 0)
                    {
                        result.IsValid = false;
                        result.Message = "A certificate reference has an empty digest value";
                        return result;
                    }

                    // Try to find the matching certificate in CertificateValues
                    bool found = false;
                    Crypto.DigestMethod refDigestMethod = Crypto.DigestMethod.GetByURI(certRef.CertDigest.DigestMethod.Algorithm);

                    foreach (EncapsulatedX509Certificate encCert in unsignedProps.CertificateValues.EncapsulatedX509CertificateCollection)
                    {
                        byte[] certHash = DigestUtil.ComputeHashValue(encCert.PkiData, refDigestMethod);
                        if (Arrays.AreEqual(certRef.CertDigest.DigestValue, certHash))
                        {
                            found = true;
                            break;
                        }
                    }

                    if (!found)
                    {
                        result.IsValid = false;
                        result.Message = "A certificate reference does not match any certificate in CertificateValues";
                        return result;
                    }
                }
            }

            return result;
        }

        /// <summary>
        /// Validates SigAndRefsTimeStamp (XAdES-X level).
        /// Verifies that the timestamp covers SignatureValue + SignatureTimeStamp +
        /// CompleteCertificateRefs + CompleteRevocationRefs.
        /// </summary>
        private ValidationResult ValidateSigAndRefsTimeStamp(SignatureDocument sigDocument)
        {
            var result = new ValidationResult();
            var unsignedProps = sigDocument.XadesSignature.UnsignedProperties.UnsignedSignatureProperties;

            TimeStamp sigAndRefsTs = unsignedProps.SigAndRefsTimeStampCollection[0];
            TimeStampToken token = new TimeStampToken(new CmsSignedData(sigAndRefsTs.EncapsulatedTimeStamp.PkiData));

            byte[] tsHashValue = token.TimeStampInfo.GetMessageImprintDigest();
            Crypto.DigestMethod tsDigestMethod = Crypto.DigestMethod.GetByOid(token.TimeStampInfo.HashAlgorithm.Algorithm.Id);

            ArrayList signatureValueElementXpaths = new ArrayList
            {
                "ds:SignatureValue",
                "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:SignatureTimeStamp",
                "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:CompleteCertificateRefs",
                "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:CompleteRevocationRefs"
            };
            byte[] computedHash = DigestUtil.ComputeHashValue(XMLUtil.ComputeValueOfElementList(sigDocument.XadesSignature, signatureValueElementXpaths), tsDigestMethod);

            if (!Arrays.AreEqual(tsHashValue, computedHash))
            {
                result.IsValid = false;
                result.Message = "The SigAndRefsTimeStamp imprint does not match the computed hash of the covered elements";
                return result;
            }

            result.IsValid = true;
            return result;
        }

        /// <summary>
        /// Validates RefsOnlyTimeStamp (XAdES-X level, alternative variant).
        /// Verifies that the timestamp covers CompleteCertificateRefs +
        /// CompleteRevocationRefs only (not SignatureValue).
        /// </summary>
        private ValidationResult ValidateRefsOnlyTimeStamp(SignatureDocument sigDocument)
        {
            var result = new ValidationResult();
            var unsignedProps = sigDocument.XadesSignature.UnsignedProperties.UnsignedSignatureProperties;

            TimeStamp refsOnlyTs = unsignedProps.RefsOnlyTimeStampCollection[0];
            TimeStampToken token = new TimeStampToken(new CmsSignedData(refsOnlyTs.EncapsulatedTimeStamp.PkiData));

            byte[] tsHashValue = token.TimeStampInfo.GetMessageImprintDigest();
            Crypto.DigestMethod tsDigestMethod = Crypto.DigestMethod.GetByOid(token.TimeStampInfo.HashAlgorithm.Algorithm.Id);

            ArrayList refsElementXpaths = new ArrayList
            {
                "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:CompleteCertificateRefs",
                "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:CompleteRevocationRefs"
            };
            byte[] computedHash = DigestUtil.ComputeHashValue(XMLUtil.ComputeValueOfElementList(sigDocument.XadesSignature, refsElementXpaths), tsDigestMethod);

            if (!Arrays.AreEqual(tsHashValue, computedHash))
            {
                result.IsValid = false;
                result.Message = "The RefsOnlyTimeStamp imprint does not match the computed hash of the referenced elements";
                return result;
            }

            result.IsValid = true;
            return result;
        }

        /// <summary>
        /// Validates CertificateValues (XAdES-XL level).
        /// Verifies that the number of embedded certificates is consistent with
        /// the number of certificate references, and that RevocationValues are
        /// present when CompleteRevocationRefs exist.
        /// </summary>
        private ValidationResult ValidateCertificateValues(SignatureDocument sigDocument)
        {
            var result = new ValidationResult { IsValid = true };
            var unsignedProps = sigDocument.XadesSignature.UnsignedProperties.UnsignedSignatureProperties;

            if (unsignedProps.CompleteCertificateRefs != null && unsignedProps.CompleteCertificateRefs.HasChanged())
            {
                int refCount = unsignedProps.CompleteCertificateRefs.CertRefs.CertCollection.Count;
                int valueCount = unsignedProps.CertificateValues.EncapsulatedX509CertificateCollection.Count;

                if (valueCount < refCount)
                {
                    result.IsValid = false;
                    result.Message = string.Format(
                        "CertificateValues contains {0} certificates but CompleteCertificateRefs has {1} references",
                        valueCount, refCount);
                    return result;
                }
            }

            // Verify RevocationValues are present when CompleteRevocationRefs exist
            if (unsignedProps.CompleteRevocationRefs != null && unsignedProps.CompleteRevocationRefs.HasChanged())
            {
                if (unsignedProps.RevocationValues == null || !unsignedProps.RevocationValues.HasChanged())
                {
                    result.IsValid = false;
                    result.Message = "CompleteRevocationRefs is present but RevocationValues is missing";
                    return result;
                }
            }

            return result;
        }

        /// <summary>
        /// Validates ArchiveTimeStamp elements (XAdES-A level).
        /// Verifies that each ArchiveTimeStamp contains a structurally valid
        /// timestamp token.
        /// </summary>
        private ValidationResult ValidateArchiveTimeStamps(SignatureDocument sigDocument)
        {
            var result = new ValidationResult();
            var unsignedProps = sigDocument.XadesSignature.UnsignedProperties.UnsignedSignatureProperties;

            for (int i = 0; i < unsignedProps.ArchiveTimeStampCollection.Count; i++)
            {
                TimeStamp archiveTs = unsignedProps.ArchiveTimeStampCollection[i];

                if (archiveTs.EncapsulatedTimeStamp == null || archiveTs.EncapsulatedTimeStamp.PkiData == null)
                {
                    result.IsValid = false;
                    result.Message = string.Format("ArchiveTimeStamp #{0} has no encapsulated timestamp", i + 1);
                    return result;
                }

                try
                {
                    TimeStampToken token = new TimeStampToken(new CmsSignedData(archiveTs.EncapsulatedTimeStamp.PkiData));

                    // Verify the timestamp token is structurally valid
                    if (token.TimeStampInfo == null)
                    {
                        result.IsValid = false;
                        result.Message = string.Format("ArchiveTimeStamp #{0} has invalid timestamp token structure", i + 1);
                        return result;
                    }
                }
                catch
                {
                    result.IsValid = false;
                    result.Message = string.Format("ArchiveTimeStamp #{0} contains an invalid timestamp token", i + 1);
                    return result;
                }
            }

            result.IsValid = true;
            return result;
        }

        #endregion
    }
}
