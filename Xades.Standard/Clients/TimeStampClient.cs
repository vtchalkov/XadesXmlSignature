// --------------------------------------------------------------------------------------------------------------------
// TimeStampClient.cs
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

using FirmaXadesNet.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Tsp;
using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;

namespace FirmaXadesNet.Clients
{
    public class TimeStampClient
    {
        #region Private variables
        private string _url;
        private string _user;
        private string _password;
        #endregion

        #region Constructors

        public TimeStampClient(string url)
        {
            _url = url;
        }

        public TimeStampClient(string url, string user, string password)
            : this(url)
        {
            _user = user;
            _password = password;
        }


        #endregion

        #region Public methods

        /// <summary>
        /// Realiza la petición de sellado del hash que se pasa como parametro y devuelve la
        /// respuesta del servidor.
        /// </summary>
        /// <param name="hash"></param>
        /// <param name="digestMethod"></param>
        /// <param name="certReq"></param>
        /// <returns></returns>
        public byte[] GetTimeStamp(byte[] hash, DigestMethod digestMethod, bool certReq)
        {
            TimeStampRequestGenerator tsrq = new TimeStampRequestGenerator();
            tsrq.SetCertReq(certReq);

            BigInteger nonce = BigInteger.ValueOf(DateTime.Now.Ticks);

            TimeStampRequest tsr = tsrq.Generate(digestMethod.Oid, hash, nonce);
            byte[] data = tsr.GetEncoded();

            using var httpClient = new HttpClient();

            if (!string.IsNullOrEmpty(_user) && !string.IsNullOrEmpty(_password))
            {
                string auth = string.Format("{0}:{1}", _user, _password);
                httpClient.DefaultRequestHeaders.Authorization =
                    new System.Net.Http.Headers.AuthenticationHeaderValue("Basic",
                        Convert.ToBase64String(Encoding.Default.GetBytes(auth), Base64FormattingOptions.None));
            }

            var content = new ByteArrayContent(data);
            content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/timestamp-query");

            var res = httpClient.PostAsync(_url, content).GetAwaiter().GetResult();
            if (!res.IsSuccessStatusCode)
            {
                throw new Exception("The server returned an invalid response");
            }

            byte[] responseBytes = res.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
            using (var resStream = new MemoryStream(responseBytes))
            {
                TimeStampResponse tsRes = new TimeStampResponse(resStream);

                tsRes.Validate(tsr);

                if (tsRes.TimeStampToken == null)
                {
                    throw new Exception("The server has not returned any time stamps");
                }

                return tsRes.TimeStampToken.GetEncoded();
            }
        }

        #endregion
    }
}
