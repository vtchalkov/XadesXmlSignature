// --------------------------------------------------------------------------------------------------------------------
// XadesUpgrader.cs
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
using FirmaXadesNet.Upgraders.Parameters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FirmaXadesNet.Upgraders
{
    public enum SignatureFormat
    {
        XAdES_T,
        XAdES_C,
        XAdES_X,
        XAdES_XL,
        XAdES_A
    }

    public class XadesUpgraderService
    {
        #region Public methods

        public void Upgrade(SignatureDocument sigDocument, SignatureFormat toFormat, UpgradeParameters parameters)
        {
            SignatureDocument.CheckSignatureDocument(sigDocument);

            switch (toFormat)
            {
                case SignatureFormat.XAdES_T:
                    EnsureT(sigDocument, parameters);
                    break;

                case SignatureFormat.XAdES_C:
                    EnsureT(sigDocument, parameters);
                    EnsureC(sigDocument, parameters);
                    break;

                case SignatureFormat.XAdES_X:
                    EnsureT(sigDocument, parameters);
                    EnsureC(sigDocument, parameters);
                    EnsureX(sigDocument, parameters);
                    break;

                case SignatureFormat.XAdES_XL:
                    EnsureT(sigDocument, parameters);
                    // XL upgrader handles C + values + X timestamp in one pass
                    // for backward compatibility and atomicity
                    new XadesXLUpgrader().Upgrade(sigDocument, parameters);
                    break;

                case SignatureFormat.XAdES_A:
                    EnsureT(sigDocument, parameters);
                    // Use XL upgrader for the full C + values + X timestamp
                    if (!HasXLProperties(sigDocument))
                    {
                        new XadesXLUpgrader().Upgrade(sigDocument, parameters);
                    }
                    new XadesAUpgrader().Upgrade(sigDocument, parameters);
                    break;
            }
        }

        #endregion

        #region Private methods

        private void EnsureT(SignatureDocument sigDocument, UpgradeParameters parameters)
        {
            if (sigDocument.XadesSignature.UnsignedProperties.UnsignedSignatureProperties.SignatureTimeStampCollection.Count == 0)
            {
                new XadesTUpgrader().Upgrade(sigDocument, parameters);
            }
        }

        private void EnsureC(SignatureDocument sigDocument, UpgradeParameters parameters)
        {
            var unsignedProps = sigDocument.XadesSignature.UnsignedProperties.UnsignedSignatureProperties;
            if (unsignedProps.CompleteCertificateRefs == null || !unsignedProps.CompleteCertificateRefs.HasChanged())
            {
                new XadesCUpgrader().Upgrade(sigDocument, parameters);
            }
        }

        private void EnsureX(SignatureDocument sigDocument, UpgradeParameters parameters)
        {
            var unsignedProps = sigDocument.XadesSignature.UnsignedProperties.UnsignedSignatureProperties;
            if (unsignedProps.SigAndRefsTimeStampCollection.Count == 0 && unsignedProps.RefsOnlyTimeStampCollection.Count == 0)
            {
                new XadesXUpgrader().Upgrade(sigDocument, parameters);
            }
        }

        private bool HasXLProperties(SignatureDocument sigDocument)
        {
            var unsignedProps = sigDocument.XadesSignature.UnsignedProperties.UnsignedSignatureProperties;
            return unsignedProps.CertificateValues != null && unsignedProps.CertificateValues.HasChanged()
                && unsignedProps.RevocationValues != null && unsignedProps.RevocationValues.HasChanged()
                && unsignedProps.CompleteCertificateRefs != null && unsignedProps.CompleteCertificateRefs.HasChanged();
        }

        #endregion
    }
}
