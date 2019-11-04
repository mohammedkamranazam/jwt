# JWT
Hi there!!!

Recently I was working with Istio and Kubernetes for one of my micro service based project. I was using Istio as a gateway for all my internal micro services. 

I wanted Istio to handle the authentication validation part. Or in other words I wanted Istio to check the Bearer Token validity attached in the API request headers.

As Istio uses a JWKS (Json Web Key Set) to validate the bearer tokens, I had to provide it with one over one of the public endpoints. Most of the articles on the internet point you to the implementation which uses Auth0. Easy, quick, but paid :(

I wanted to have something workable but FREE, FREE, FREE.

So, I went on to the journey of exploring some **CRYPTOGRAPHY** stuffs, painful stuffs, confusing stuffs, so that I too can create my own JWKS and provide it to Istio so that istio can validate my Bearer Token and allow my API requests to pass through.

### JWKS Documentation
https://tools.ietf.org/html/rfc7517

### Sample JWKS
```json
{
	"keys": [{
		"n": "xxxx",
		"e": "xxxx",
		"x5c": ["xxxx"],
		"x5t": "xxxx",
		"kid": "xxxx",
		"alg": "RS256",
		"kty": "RSA",
		"use": "sig"
	}]
}
````

## Contents
1. In this article we will try to look into some of the ways to create/sign/validate a JWT Bearer Token using Dot Net Core

2. We will create some helper classes to sign/validate the Bearer Tokens using the below algorithms.

	a) Using Symmetric Key
	b) Using Asymmetric Key
	c) Using Certificate

3. We will create a middleware which will return a JSON response containing the JWKS

# Let Us Get Started
I will explain the code in next version of documentation. Right now just feed your eyes with some codes.

#### Our First Interface - To Make Things INJECTABLE
```csharp
public interface IJwtSecurityKey
{
	SecurityKey PrivateKey { get; }
	SecurityKey PublicKey { get; }
	SigningCredentials SigningCredential { get; }
	RSAParameters RsaParameters { get; set; }
	string X5C { get; set; }
	string X5T { get; set; }
}
```
#### Model To Hold The Configurations (Asymmetric Key)
```csharp
public class RSAConfig
{
	[JsonProperty("Modulus")]
	public string Modulus { get; set; }

	[JsonProperty("Exponent")]
	public string Exponent { get; set; }

	[JsonProperty("P")]
	public string P { get; set; }

	[JsonProperty("Q")]
	public string Q { get; set; }

	[JsonProperty("DP")]
	public string DP { get; set; }

	[JsonProperty("DQ")]
	public string DQ { get; set; }

	[JsonProperty("InverseQ")]
	public string InverseQ { get; set; }

	[JsonProperty("D")]
	public string D { get; set; }
}
```
#### Implementation For Asymmetric Key Based Token Signing
```csharp
public class JwtAsymmetricSecurityKey : IJwtSecurityKey
    {
        public SecurityKey PrivateKey { get; private set; }

        public SecurityKey PublicKey { get; private set; }

        public SigningCredentials SigningCredential { get; private set; }
        public RSAParameters RsaParameters { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public string X5C { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public string X5T { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

        public JwtAsymmetricSecurityKey(IConfiguration configuration)
        {
            var rsaConfig = configuration.GetSection("Token:RSAConfig").Get<RSAConfig>();
            var keyId = configuration["Token:KeyId"];

            RSAParameters rsaParams = GetRSAParamsFromConfig(rsaConfig);

            Create(rsaParams, keyId);
        }

        private void Create(RSAParameters rsaParams, string keyId)
        {
            var rsaProvider = new RSACryptoServiceProvider(2048);

            rsaProvider.ImportParameters(rsaParams);

            PublicKey = new RsaSecurityKey(rsaProvider.ExportParameters(false));

            var privateKey = new RsaSecurityKey(rsaProvider);
            privateKey.KeyId = keyId;
            PrivateKey = privateKey;

            SigningCredential = new SigningCredentials(PrivateKey, SecurityAlgorithms.RsaSha256, SecurityAlgorithms.Sha256);
        }

        private RSAParameters GetRSAParamsFromConfig(RSAConfig rsaConfig)
        {
            return new RSAParameters
            {
                Modulus = rsaConfig.Modulus != null ? Convert.FromBase64String(rsaConfig.Modulus) : null,
                Exponent = rsaConfig.Exponent != null ? Convert.FromBase64String(rsaConfig.Exponent) : null,
                P = rsaConfig.P != null ? Convert.FromBase64String(rsaConfig.P) : null,
                Q = rsaConfig.Q != null ? Convert.FromBase64String(rsaConfig.Q) : null,
                DP = rsaConfig.DP != null ? Convert.FromBase64String(rsaConfig.DP) : null,
                DQ = rsaConfig.DQ != null ? Convert.FromBase64String(rsaConfig.DQ) : null,
                InverseQ = rsaConfig.InverseQ != null ? Convert.FromBase64String(rsaConfig.InverseQ) : null,
                D = rsaConfig.D != null ? Convert.FromBase64String(rsaConfig.D) : null
            };
        }
    }
```

#### Implementation For Symmetric Key Based Token Signing
```csharp
 public class JwtSymmetricSecurityKey : IJwtSecurityKey
    {
        public JwtSymmetricSecurityKey(string secret, string keyId)
        {
            var privateKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secret));
            privateKey.KeyId = keyId;

            PrivateKey = privateKey;
            PublicKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secret));

            SigningCredential = new SigningCredentials(PrivateKey, SecurityAlgorithms.HmacSha256);
        }

        public SecurityKey PrivateKey { get; }

        public SigningCredentials SigningCredential { get; }

        public SecurityKey PublicKey { get; }

        public RSAParameters RsaParameters { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public string X5C { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public string X5T { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
    }
```

#### Implementation for Certificate Based Token Signing
```csharp
public class JwtCertificateSecurityKey : IJwtSecurityKey
    {
        public SecurityKey PrivateKey { get; private set; }

        public SecurityKey PublicKey { get; private set; }

        public SigningCredentials SigningCredential { get; private set; }

        public RSAParameters RsaParameters { get; set; }
        public string X5C { get; set; }
        public string X5T { get; set; }

        public JwtCertificateSecurityKey(X509Certificate2 x509Certificate2, string keyId)
        {
            Create(x509Certificate2, keyId);
        }

        private void Create(X509Certificate2 x509Certificate2, string keyId)
        {
            var key = new X509SecurityKey(x509Certificate2);

            var rsaProvider = (RSA)key.PrivateKey;

            var publicKey = new RsaSecurityKey(rsaProvider.ExportParameters(false));

            PublicKey = publicKey;

            var privateKey = new RsaSecurityKey(rsaProvider);
            privateKey.KeyId = keyId;
            PrivateKey = privateKey;

            SigningCredential = new SigningCredentials(PrivateKey, SecurityAlgorithms.RsaSha256, SecurityAlgorithms.Sha256);

            var chain = new X509Chain();
            chain.Build(x509Certificate2);

            X5C = Convert.ToBase64String(chain.ChainElements[0].Certificate.RawData, 0, chain.ChainElements[0].Certificate.RawData.Length);
            X5T = Base64UrlEncoder.Encode(chain.ChainElements[0].Certificate.Thumbprint);

            RsaParameters = publicKey.Parameters;
        }
    }
```

#### Token Class
```csharp
public sealed class JwtToken
    {
        private readonly JwtSecurityToken _token;

        internal JwtToken(JwtSecurityToken token)
        {
            _token = token;
        }

        public DateTime ValidTo => _token.ValidTo;

        public string Value => new JwtSecurityTokenHandler().WriteToken(_token);
    }
```

#### Token Builder Class
```csharp
public sealed class JwtTokenBuilder
    {
        private Dictionary<string, object> _claims = new Dictionary<string, object>();

        private double _ExpiryInMinutes;

        private string Audience;

        private DateTime ExpiryTime;

        private string Issuer;

        private string Subject;

        private readonly IJwtSecurityKey _jwtSecurityKey;

        public JwtTokenBuilder(IConfiguration configuration,
            IJwtSecurityKey jwtSecurityKey)
        {
            Issuer = configuration["Token:ValidIssuer"];
            Audience = configuration["Token:ValidAudience"];
            _ExpiryInMinutes = int.Parse(configuration["Token:ExpiryInMinutes"], CultureInfo.InvariantCulture);
            _jwtSecurityKey = jwtSecurityKey;
        }


        public JwtTokenBuilder AddAudience(string audience)
        {
            Audience = audience;
            return this;
        }

        public JwtTokenBuilder AddClaim(string type, object value)
        {
            _claims.Add(type, value);
            return this;
        }

        public JwtTokenBuilder AddClaims(Dictionary<string, object> claims)
        {
            _claims = _claims.MergeLeft(claims);
            return this;
        }

        public JwtTokenBuilder AddExpiryByMinutes(double expiryInMinutes)
        {
            _ExpiryInMinutes = expiryInMinutes;
            return this;
        }

        public JwtTokenBuilder AddExpiryByTime(DateTime expiryTime)
        {
            ExpiryTime = expiryTime;
            return this;
        }

        public JwtTokenBuilder AddIssuer(string issuer)
        {
            Issuer = issuer;
            return this;
        }

        public JwtTokenBuilder AddSubject(string subject)
        {
            Subject = subject;
            return this;
        }

        public JwtToken Build(bool byMinutes = true)
        {
            EnsureArguments();

            var claims = new List<Claim>
                             {
                                 new Claim(JwtRegisteredClaimNames.Sub, Subject),
                                 new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                             }
            .Union(_claims.Select(item => new Claim(item.Key, item.Value.ToString())));

            var token = new JwtSecurityToken(
                              issuer: Issuer,
                              audience: Audience,
                              claims: claims,
                              expires: byMinutes ? DateTime.UtcNow.AddMinutes(_ExpiryInMinutes) : ExpiryTime,
                              signingCredentials: _jwtSecurityKey.SigningCredential);

            return new JwtToken(token);
        }

        #region " private "

        private void EnsureArguments()
        {
            if (string.IsNullOrEmpty(Subject))
            {
                throw new ArgumentNullException(nameof(Subject));
            }

            if (string.IsNullOrEmpty(Issuer))
            {
                throw new ArgumentNullException(nameof(Issuer));
            }

            if (string.IsNullOrEmpty(Audience))
            {
                throw new ArgumentNullException(nameof(Audience));
            }
        }

        #endregion " private "
    }
```
#### JWKS Endpoint Middleware
```csharp
app.Map("/api/auth/jwks",
                builder => builder.Run(context =>
                    {
                        var modulus = Base64UrlEncoder.Encode(JwtSecurityKey.RsaParameters.Modulus);
                        var exponent = Base64UrlEncoder.Encode(JwtSecurityKey.RsaParameters.Exponent);

                        var jwks = new
                        {
                            keys = new List<dynamic> { new {
                                    n = modulus,
                                    e = exponent,
                                    x5c = new List<string> { JwtSecurityKey.X5C },
                                    x5t = JwtSecurityKey.X5T,
                                    kid = Configuration["Token:KeyId"],
                                    alg = SecurityAlgorithms.RsaSha256,
                                    kty = "RSA",
                                    use = "sig"
                                }
                            }
                        };
                        return context.Response.WriteAsync(JsonConvert.SerializeObject(jwks));
                    }));
```

#### Injecting JWT Token Builder and Services Into Startup.cs + Token Scheme For Authentication
```csharp
public void ConfigureServices(IServiceCollection services)
{
	//JwtSecurityKey = GetJwtAssymmetricSecurityKey();
	//JwtSecurityKey = GetJwtSymmetricSecurityKey();

	JwtSecurityKey = GetJwtCertificateSecurityKey();

	services.AddSingleton(typeof(IJwtSecurityKey), JwtSecurityKey);

	services.AddSingleton(typeof(JwtTokenBuilder));
	
	 var authorization = new AuthorizationPolicyBuilder()
	 .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme)
	 .RequireAuthenticatedUser().Build();

	services.AddAuthorization(options =>
	{
		options.AddPolicy("Bearer", authorization);
	}
	
	services.AddAuthentication(options =>
	{
		options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
		options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;

		authenticationAction?.Invoke(options);
	})
	.AddJwtBearer(options =>
	{
		options.TokenValidationParameters = new TokenValidationParameters
		{
			ValidateLifetime = true,

			ValidateIssuer = true,
			ValidIssuer = configuration["ValidIssuer"],

			ValidateAudience = true,
			ValidAudience = configuration["ValidAudience"],

			ValidateIssuerSigningKey = true,
			IssuerSigningKey = jwtSecurityKey.PublicKey,

			ClockSkew = TimeSpan.Zero
		};

		options.Events = new JwtBearerEvents
		{
			OnMessageReceived = messageReceivedContext => { return Task.CompletedTask; },
			OnChallenge = challengeContext =>
			{
				challengeContext.HandleResponse();
				challengeContext.Response.StatusCode = 419;

				return Task.CompletedTask;
			},
			OnAuthenticationFailed = authenticationFailedContext => { return Task.CompletedTask; },
			OnTokenValidated = tokenValidatedContext => { return Task.CompletedTask; }
		};

		jwtAction?.Invoke(options);
	});
}

private JwtSymmetricSecurityKey GetJwtSymmetricSecurityKey()
{
	var secret = Configuration["Token:SigningKey"];
	var keyId = Configuration["Token:KeyId"];

	return new JwtSymmetricSecurityKey(secret, keyId);
}

private JwtCertificateSecurityKey GetJwtCertificateSecurityKey()
{
	var x509Certificate2 = GetX509Certificate();

	string keyId = Configuration["Token:KeyId"];

	return new JwtCertificateSecurityKey(x509Certificate2, keyId);
}

private JwtAsymmetricSecurityKey GetJwtAssymmetricSecurityKey()
{
	return new JwtAsymmetricSecurityKey(Configuration);
}

private X509Certificate2 GetX509Certificate()
{
	var pfxPath = Configuration["Token:PfxPath"];
	var pfxPassword = Configuration["Token:PfxPassword"];
	return new X509Certificate2(pfxPath, pfxPassword);
}
```
#### Building Token
```csharp
//jwtTokenBuilder -> Injected JwtTokenBuilder instance in the constructor
var token = jwtTokenBuilder
                  .AddClaims(claims)
                  .AddSubject("Token_Subject")
                  .AddExpiryByTime(expiryTime)
                  .Build(byMinutes);

return $"Bearer {token.Value}";
```
#### AppSettings.json
```json
  "Token": {
  	"PfxPath": "certificate.pfx",
  	"PfxPassword": "xxxxxxxxxxxxxx",
  	"SigningKey": "xxxxxxxxxxxxxx",
  	"KeyId": "123454321",
  	"ValidIssuer": "",
  	"ValidAudience": "",
  	"ExpiryInMinutes": 5,
  	"RefreshTokenExpiryInMinutes": 60,
  	"RSAConfig": {
  		"Modulus": "xxxxxxxxxxxxxx==",
  		"Exponent": "xxxx",
  		"P": "xxxxxxxxxxxxxx=",
  		"Q": "xxxxxxxxxxxxxx=",
  		"DP": "xxxxxxxxxxxxxx=",
  		"DQ": "xxxxxxxxxxxxxx=",
  		"InverseQ": "xxxxxxxxxxxxxx=",
  		"D": "xxxxxxxxxxxxxx=="
  	}
  }
```
#### Powershell Script To Create Public Key + Private Key For Asymmetric Token Signing
Once the public and private keys are created, extract the XML values and put them in the appSettings.json file to serve as an input config for the Asymmetric Key based token signing.
```bash
$rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider -ArgumentList 2048
$rsa.toXmlString($true) | Out-File $SavePath\private-key.xml
$rsa.toXmlString($false) | Out-File $SavePath\public-key.xml 
```
#### Command To Create Certificate.PFX Using Visual Studio Developer Console
```bash
makecert -r -pe -n "CN=contoso.com" -sky exchange -sv contoso.com.pvk contoso.com.cer

pvk2pfx -pvk contoso.com.pvk -spc contoso.com.cer -pfx contoso.com.pfx
```
