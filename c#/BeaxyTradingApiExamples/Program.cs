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

        private static Session _currentSession;
        private static HMACSHA384 _hmac;

        static async Task Main()
        {
            _currentSession = await OpenSessionAsync();
            _hmac = new HMACSHA384(ConvertBigIntToByteArray(_currentSession.SessionSecret));

            var accounts = await GetAccountsAsync();
            // var order = await PlaceOrderAsync();
            // var orders = await GetOrderHistoryAsync(startFrom: DateTimeOffset.UtcNow.AddHours(-5).ToUnixTimeMilliseconds());
            // var openOrders = await GetOpenOrdersAsync();
            
            Console.WriteLine(string.Join(',', accounts.Select(x => x.CurrencyId)));
            Console.Read();

            _hmac.Dispose();
        }

        static async Task<List<AccountResponse>> GetAccountsAsync()
        {
            using var client = new HttpClient()
            {
                BaseAddress = new Uri(BASE_ADDRESS),
            };

            var path = "/api/v1/accounts";
            var headers = new List<KeyValuePair<string, string>>
            {
                new KeyValuePair<string, string>("X-Deltix-Nonce", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString()),
                new KeyValuePair<string, string>("X-Deltix-Session-Id", _currentSession.SessionId),
            };

            foreach (var header in headers)
            {
                client.DefaultRequestHeaders.Add(header.Key, header.Value);
            }

            var payload = BuildPayload("GET", path, new List<KeyValuePair<string, string>>(), headers);

            client.DefaultRequestHeaders.Add("X-Deltix-Signature",
                Convert.ToBase64String(
                    _hmac.ComputeHash(Encoding.UTF8.GetBytes(payload))));

            var accountsResult = await client.GetAsync(path);
            var accountsJson = await accountsResult.Content.ReadAsStringAsync();
            return JsonConvert.DeserializeObject<List<AccountResponse>>(accountsJson);
        }

        static async Task<OrderResponse> PlaceOrderAsync()
        {
            using var client = new HttpClient()
            {
                BaseAddress = new Uri(BASE_ADDRESS),
            };

            var path = "/api/v1/orders";
            var headers = new List<KeyValuePair<string, string>>
                {
                    new KeyValuePair<string, string>("X-Deltix-Nonce", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString()),
                    new KeyValuePair<string, string>("X-Deltix-Session-Id", _currentSession.SessionId),
                };

            var body = JsonConvert.SerializeObject(new
            {
                security_id = "BXYBTC",
                type = "limit",
                side = "sell",
                quantity = "109",
                price = "0.00000150",
                time_in_force = "gtc",
                destination = "MAXI"
            });

            foreach (var header in headers)
            {
                client.DefaultRequestHeaders.Add(header.Key, header.Value);
            }

            var payload = BuildPayload("POST", path, new List<KeyValuePair<string, string>>(), headers, body);

            client.DefaultRequestHeaders.Add("X-Deltix-Signature",
                Convert.ToBase64String(
                    _hmac.ComputeHash(Encoding.UTF8.GetBytes(payload))));


            var placeOrderResult = await client.PostAsync(path,
                new StringContent(body, Encoding.UTF8, "application/json"));

            var placeOrderJson = await placeOrderResult.Content.ReadAsStringAsync();

            return JsonConvert.DeserializeObject<OrderResponse>(placeOrderJson);
        }

        static async Task<List<OrderResponse>> GetOrderHistoryAsync(long startFrom = 0, int count = 100)
        {
            using var client = new HttpClient()
            {
                BaseAddress = new Uri(BASE_ADDRESS),
            };

            var path = "/api/v1/orders/history";
            var headers = new List<KeyValuePair<string, string>>
            {
                new KeyValuePair<string, string>("X-Deltix-Nonce", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString()),
                new KeyValuePair<string, string>("X-Deltix-Session-Id", _currentSession.SessionId),
            };

            var queryParams = new List<KeyValuePair<string, string>>
            {
                new KeyValuePair<string, string>("startTime", startFrom.ToString()),
                new KeyValuePair<string, string>("count", count.ToString()),
            };

            foreach (var header in headers)
            {
                client.DefaultRequestHeaders.Add(header.Key, header.Value);
            }

            var payload = BuildPayload("GET", path, queryParams, headers);

            client.DefaultRequestHeaders.Add("X-Deltix-Signature",
                Convert.ToBase64String(
                    _hmac.ComputeHash(Encoding.UTF8.GetBytes(payload))));

            var closedOrdersResult = await client.GetAsync($"{path}?count={count}&startTime={startFrom}");

            var closedOrdersJson = await closedOrdersResult.Content.ReadAsStringAsync();

            return JsonConvert.DeserializeObject<List<OrderResponse>>(closedOrdersJson);
        }

        static async Task<List<OrderResponse>> GetOpenOrdersAsync()
        {
            using var client = new HttpClient()
            {
                BaseAddress = new Uri(BASE_ADDRESS),
            };

            var path = "/api/v1/orders";
            var headers = new List<KeyValuePair<string, string>>
                {
                    new KeyValuePair<string, string>("X-Deltix-Nonce", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString()),
                    new KeyValuePair<string, string>("X-Deltix-Session-Id", _currentSession.SessionId),
                };

            foreach (var header in headers)
            {
                client.DefaultRequestHeaders.Add(header.Key, header.Value);
            }

            var payload = BuildPayload("GET", path, new List<KeyValuePair<string, string>>(), headers);

            client.DefaultRequestHeaders.Add("X-Deltix-Signature",
                Convert.ToBase64String(
                    _hmac.ComputeHash(Encoding.UTF8.GetBytes(payload))));

            var ordersResult = await client.GetAsync(path);
            var ordersJson = await ordersResult.Content.ReadAsStringAsync();

            return JsonConvert.DeserializeObject<List<OrderResponse>>(ordersJson);
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
                             new BigInteger(Convert.FromBase64String(loginConfirm.DhKey), false, true), dhNumber, dhModulus)
            };
        }

        static string BuildPayload(
           string httpMethod,
           string path,
           List<KeyValuePair<string, string>> queryParams,
           List<KeyValuePair<string, string>> headers,
           string body = null)
        {
            return $"{httpMethod.ToUpper()}{path.ToLower()}{string.Join('&', queryParams.OrderBy(x => x.Key).Select(x => $"{x.Key.ToLower()}={x.Value}"))}{string.Join('&', headers.OrderBy(x => x.Key).Select(x => $"{x.Key}={x.Value}"))}{body}";
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

        class OrderResponse
        {
            public string Id { get; set; }

            public string Status { get; set; }
        }
    }
}
