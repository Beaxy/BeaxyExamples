using Newtonsoft.Json;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace BeaxyTradingApiExamples
{
    class Program
    {
        const string API_KEY = "<API_KEY>";
        const string PRIVATE_KEY = "<PRIVATE_KEY>";
        const string BASE_ADDRESS = "https://tradingapi.beaxy.com";

        static async Task Main()
        {
            var session = await OpenSessionAsync();
            var accounts = await GetAccountsAsync(session);

            Console.WriteLine(string.Join(',', accounts.Select(x => x.CurrencyId)));
            Console.Read();
        }

        static async Task<List<AccountResponse>> GetAccountsAsync(Session session)
        {
            using var hmac = new HMACSHA384(ConvertBigIntToByteArray(session.SessionSecret));
            using var client = new HttpClient()
            {
                BaseAddress = new Uri(BASE_ADDRESS),
            };

            var path = "/api/v1/accounts";
            var headers = new List<KeyValuePair<string, string>>
            {
                new KeyValuePair<string, string>("X-Deltix-Nonce", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString()),
                new KeyValuePair<string, string>("X-Deltix-Session-Id", session.SessionId),
            };

            foreach (var header in headers)
            {
                client.DefaultRequestHeaders.Add(header.Key, header.Value);
            }

            var payload = BuildPayload("GET", path, new List<KeyValuePair<string, string>>(), headers);

            client.DefaultRequestHeaders.Add("X-Deltix-Signature",
                Convert.ToBase64String(
                    hmac.ComputeHash(Encoding.UTF8.GetBytes(payload))));

            var accountsResult = await client.GetAsync(path);
            var accountsJson = await accountsResult.Content.ReadAsStringAsync();
            return JsonConvert.DeserializeObject<List<AccountResponse>>(accountsJson);
        }

        static async Task<Session> OpenSessionAsync()
        {
            using var client = new HttpClient()
            {
                BaseAddress = new Uri(BASE_ADDRESS),
            };

            //--------Login Attempt----------
            var loginAttemptResult = await client.PostAsync("/api/v1/login/attempt",
                new StringContent(JsonConvert.SerializeObject(new
                {
                    api_key_id = API_KEY,
                }), Encoding.UTF8, "application/json"));

            var loginAttempt = JsonConvert.DeserializeObject<LoginAttemptResponse>(await loginAttemptResult.Content.ReadAsStringAsync());

            //--------Login Confirm---------- 
            var dhModulus = new BigInteger(Convert.FromBase64String(loginAttempt.DhModulus), false, true);
            var dhBase = new BigInteger(Convert.FromBase64String(loginAttempt.DhBase), false, true);
            var dhNumber = GetRandomBigInt();

            var signedChallange = SignChallange(loginAttempt.Challenge);
            var dhKey = Convert.ToBase64String(BigInteger.ModPow(dhBase, dhNumber, dhModulus).ToByteArray(false, true));

            var loginConfirmResult = await client.PostAsync("/api/v1/login/confirm",
                new StringContent(JsonConvert.SerializeObject(new
                {
                    session_id = loginAttempt.SessionId,
                    signature = signedChallange,
                    dh_key = dhKey,
                }), Encoding.UTF8, "application/json"));

            var loginConfirm = JsonConvert.DeserializeObject<LoginConfirmResponse>(await loginConfirmResult.Content.ReadAsStringAsync());

            return new Session
            {
                SessionId = loginAttempt.SessionId,
                SessionSecret = BigInteger.ModPow(
                             new BigInteger(Convert.FromBase64String(loginConfirm.DhKey), false, true),dhNumber, dhModulus)
            };
        }

        static string BuildPayload(
           string httpMethod,
           string path,
           List<KeyValuePair<string, string>> queryParams,
           List<KeyValuePair<string, string>> headers,
           string body = null)
        {
            return $"{httpMethod.ToUpper()}{path.ToLower()}{string.Join('&', queryParams.OrderBy(x => x.Key).Select(x => $"{x.Key}={x.Value}"))}{string.Join('&', headers.OrderBy(x => x.Key).Select(x => $"{x.Key}={x.Value}"))}{body}";
        }

        static BigInteger GetRandomBigInt()
        {
            var rng = new RNGCryptoServiceProvider();
            byte[] bytes = new byte[512 / 8];
            rng.GetBytes(bytes);

            return new BigInteger(bytes, true, true);
        }

        static string SignChallange(string challange)
        {
            var pem = $"-----BEGIN PRIVATE KEY-----\n{ PRIVATE_KEY}\n-----END PRIVATE KEY-----";
            var pr = new PemReader(new StringReader(pem));
            var privateKeyParam = (AsymmetricKeyParameter)pr.ReadObject();
            var rsaParams = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)privateKeyParam);

            var csp = new RSACryptoServiceProvider();
            csp.ImportParameters(rsaParams);

            return Convert.ToBase64String(
                csp.SignData(
                    Convert.FromBase64String(challange),
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1));
        }

        public static byte[] ConvertBigIntToByteArray(BigInteger bigInt)
        {
            return bigInt.ToByteArray().Reverse().ToArray();
        }

        class Session
        {
            public string SessionId { get; set; }
            public BigInteger SessionSecret { get; set; }
        }

        class LoginAttemptResponse
        {
            [JsonProperty("session_id")]
            public string SessionId { get; set; }

            public string Challenge { get; set; }

            [JsonProperty("dh_base")]
            public string DhBase { get; set; }

            [JsonProperty("dh_modulus")]
            public string DhModulus { get; set; }
        }

        class LoginConfirmResponse
        {
            [JsonProperty("dh_key")]
            public string DhKey { get; set; }
        }

        class AccountResponse
        {
            [JsonProperty("currency_id")]
            public string CurrencyId { get; set; }
        }
    }
}
