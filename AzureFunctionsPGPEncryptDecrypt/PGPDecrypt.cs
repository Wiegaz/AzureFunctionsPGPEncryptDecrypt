using System.IO;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using PgpCore;
using System.Threading.Tasks;
using System;
using System.Text;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Bcpg.OpenPgp;

namespace AzureFunctionsPGPEncryptDecrypt
{
    public static class PGPDecrypt
    {
        [FunctionName(nameof(PGPDecrypt))]
        public static async Task<IActionResult> RunAsync([HttpTrigger(AuthorizationLevel.Function, "post")] HttpRequest req, ILogger log)
        {
            log.LogInformation($"C# HTTP trigger function {nameof(PGPDecrypt)} processed a request.");

            string privateKeyBase64 = Environment.GetEnvironmentVariable("pgp-private-key");
            string passPhrase = Environment.GetEnvironmentVariable("pgp-passphrase");

            if (string.IsNullOrEmpty(privateKeyBase64))
            {
                return new BadRequestObjectResult($"Please add a base64 encoded private key to an environment variable called pgp-private-key");
            }

            byte[] privateKeyBytes = Convert.FromBase64String(privateKeyBase64);
            string privateKey = Encoding.UTF8.GetString(privateKeyBytes);

            try
            {
                Stream decryptedData = await DecryptAsync(req.Body, privateKey, passPhrase);
                return new OkObjectResult(decryptedData);
            }
            catch (PgpException pgpException)
            {
                return new BadRequestObjectResult(pgpException.Message);
            }
        }

        private static async Task<Stream> DecryptAsync(Stream inputStream, string privateKey, string passPhrase)
        {
            using (PGP pgp = new PGP())
            {
                Stream outputStream = new MemoryStream();

                using (inputStream)
                using (Stream privateKeyStream = privateKey.ToStream())
                {
                    await pgp.DecryptStreamAsync(inputStream, outputStream, privateKeyStream, passPhrase);
                    outputStream.Seek(0, SeekOrigin.Begin);
                    return outputStream;
                }
            }
        }
    }
}
