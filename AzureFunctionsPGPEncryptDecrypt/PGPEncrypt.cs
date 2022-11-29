using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System.Text;
using PgpCore;
using Org.BouncyCastle.Bcpg.OpenPgp;

namespace AzureFunctionsPGPEncryptDecrypt
{
    public static class PGPEncrypt
    {
        [FunctionName(nameof(PGPEncrypt))]
        public static async Task<IActionResult> RunAsync([HttpTrigger(AuthorizationLevel.Function, "post")] HttpRequest req, ILogger log)
        {
            log.LogInformation($"C# HTTP trigger function {nameof(PGPEncrypt)} processed a request.");

            string publicKeyBase64 = Environment.GetEnvironmentVariable("pgp-public-key");

            if (string.IsNullOrEmpty(publicKeyBase64))
            {
                return new BadRequestObjectResult($"Please add a base64 encoded public key to an environment variable called pgp-public-key");
            }

            byte[] publicKeyBytes = Convert.FromBase64String(publicKeyBase64);
            string publicKey = Encoding.UTF8.GetString(publicKeyBytes);

            req.EnableBuffering(); //Make RequestBody Stream seekable

            try
            {
                Stream encryptedData = await EncryptAsync(req.Body, publicKey);
                return new OkObjectResult(encryptedData);
            }
            catch (PgpException pgpException)
            {
                return new BadRequestObjectResult(pgpException.Message);
            }
        }

        private static async Task<Stream> EncryptAsync(Stream inputStream, string publicKey)
        {
            using (PGP pgp = new PGP())
            {
                Stream outputStream = new MemoryStream();

                using (inputStream)
                using (Stream publicKeyStream = publicKey.ToStream())
                {
                    await pgp.EncryptStreamAsync(inputStream, outputStream, publicKeyStream, true, true);
                    outputStream.Seek(0, SeekOrigin.Begin);
                    return outputStream;
                }
            }
        }
    }
}
