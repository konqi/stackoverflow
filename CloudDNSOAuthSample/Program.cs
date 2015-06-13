/*
Copyright 2011 Google Inc

Licensed under the Apache License, Version 2.0(the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

using Google.Apis.Auth.OAuth2;
using Google.Apis.Auth.OAuth2.Responses;
using Google.Apis.Dns.v1;
using Google.Apis.Dns.v1.Data;
using Google.Apis.Services;
using Google.Apis.Util.Store;

namespace CloudDns.ListMyZones
{
    /// <summary>
    /// Sample which demonstrates how to use the Books API.
    /// Lists all volumes in the the users library, and retrieves more detailed information about the first volume.
    /// https://code.google.com/apis/books/docs/v1/getting_started.html
    /// </summary>
    internal class Program
    {
        String clientSecret = "eznSyjqqchaYkPLGW9hTq54h";
        String clientId = "510734317878-pkhcit9ctvh10mpnhfmojae1h6lejhmo.apps.googleusercontent.com";
        String projectId = "CloudDNS-projectId";

        [STAThread]
        static void Main(string[] args)
        {
            Console.WriteLine("Books API Sample: List MyLibrary");
            Console.WriteLine("================================");

            try
            {
                new Program().Run().Wait();
            }
            catch (AggregateException ex)
            {
                foreach (var e in ex.InnerExceptions)
                {
                    Console.WriteLine("ERROR: " + e.Message);
                }
            }

            Console.WriteLine("Press any key to continue...");
            Console.ReadKey();
        }

        private async Task Run()
        {
            UserCredential credential;


            using (var memstream = new MemoryStream())
            {
                // Ugly way of providing clientId & Secret inmemory
                var writer = new StreamWriter(memstream);
                writer.Write(@"{""installed"":{""auth_uri"":""https://accounts.google.com/o/oauth2/auth"",""client_secret"":""");
                writer.Write(clientSecret);
                writer.Write(@""",""token_uri"":""https://accounts.google.com/o/oauth2/token"",""client_email"":"""",""redirect_uris"":[""urn:ietf:wg:oauth:2.0:oob"",""oob""],""client_x509_cert_url"":"""",""client_id"":""");
                writer.Write(clientId);
                writer.Write(@""",""auth_provider_x509_cert_url"":""https://www.googleapis.com/oauth2/v1/certs""}}");
                writer.Flush();
                memstream.Position = 0;

                credential = await GoogleWebAuthorizationBroker.AuthorizeAsync(
                    GoogleClientSecrets.Load(memstream).Secrets,
                    new[] { DnsService.Scope.NdevClouddnsReadwrite},
                    "user", CancellationToken.None, new FileDataStore("Books.ListMyLibrary"));
            }

            // Create the service.
            var service = new DnsService(new BaseClientService.Initializer()
                {
                    HttpClientInitializer = credential,
                    ApplicationName = "Cloud DNS API Sample",
                });

            // List library.
            await ListZones(service);

            //// Revoke the credential.
            //Console.WriteLine("\n!!!REVOKE ACCESS TOKEN!!!\n");
            //await credential.RevokeTokenAsync(CancellationToken.None);

            //// Request should fail now - invalid grant.
            //try
            //{
            //    await ListZones(service);
            //}
            //catch (TokenResponseException ex)
            //{
            //    Console.WriteLine(ex.Error);
            //}

            //// Reauthorize the user. A browser should be opened, and the user should enter his or her credential again.
            //await GoogleWebAuthorizationBroker.ReauthorizeAsync(credential, CancellationToken.None);

            //// The request should succeed now.
            //await ListZones(service);
        }

        private async Task ListZones(DnsService service)
        {
            Console.WriteLine("\n\n\nListing Managed Zones... (Execute ASYNC)");
            Console.WriteLine("===========================================");

            // Execute async.
            var managedZones = await service.ManagedZones.List(projectId).ExecuteAsync();
            foreach (var zone in managedZones.ManagedZones)
            {
                Console.WriteLine(zone.DnsName);
            }
        }
    }
}
