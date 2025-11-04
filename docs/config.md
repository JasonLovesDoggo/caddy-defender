# **Configuration**

### **Caddyfile Syntax**

The `defender` directive is used to configure the Caddy Defender plugin. It has the following syntax:

```caddyfile
defender <responder> {
    message <custom_message>
    status_code <http_status_code>
    ranges <cidr_or_predefined...>
    url <url>
}
```

- `<responder>`: The responder backend to use.
- `<cidr_or_predefined>`: An optional list of CIDR ranges or predefined range keys to match against the client's IP. Defaults to [`aws azurepubliccloud deepseek gcloud githubcopilot openai`](https://github.com/JasonLovesDoggo/caddy-defender/blob/main/plugin.go).
- `<custom_message>`: A custom message to return when using the `custom` responder.
- `<http_status_code>`: An optional HTTP status code to return when using the `custom` responder. Defaults to 200.
- `<url>`: The URI that the `redirect` responder would redirect to.

#### **Supported responder types:**

- `block`: Returns a `403 Forbidden` response.
- `custom`: Returns a custom message with configurable status code (requires `message`, optional `status_code` defaults to 200).
- `drop`: Drops the connection.
- `garbage`: Returns garbage data to pollute AI training.
- `redirect`: Returns a `308 Permanent Redirect` response (requires `url`).
- `ratelimit`: Marks requests for rate limiting (requires [Caddy-Ratelimit](https://github.com/mholt/caddy-ratelimit) to be installed as well ).
- `tarpit`: Stream data at a slow, but configurable rate to stall bots and pollute AI training.

### **JSON Configuration**

```JSON
{
	"message": "",
	"status_code": 0,
	"url": "",
	"raw_responder": "",
	"ranges": [""],
	"whitelist": [""],
	"tarpit_config": {
		"headers": {
			"": ""
		},
		"timeout": 0,
		"bytes_per_second": 0,
		"code": 0
	},
	"serve_ignore": false
}
```

`message`

- Message specifies the custom response message for `custom` responder type. Required when using `custom` responder.

`status_code`

- StatusCode specifies the HTTP status code for `custom` responder type. Optional. Default: 200.
- Can be set to any valid HTTP status code (e.g., 200, 403, 404, 451, 503).

`url`

- URL specifies the custom URL to redirect clients to for `redirect` responder type. Required only when using `redirect` responder.

`raw_responder`

- RawResponder defines the response strategy for blocked requests. **Required**.
- Must be one of the [supported responder types](#supported-responder-types), (e.g "block", "drop", etc.).

`ranges`

- Ranges specifies IP ranges to block, which can be either:
  - CIDR notations (e.g., "192.168.1.0/24")
  - Predefined service keys (e.g., "openai", "aws") Default:

`whitelist`

- An optional whitelist of IP addresses to exclude from blocking.
  - NOTE: this only supports IP addresses, not ranges.
- If empty, no IPs are whitelisted.
- Default: `[]`

`tarpit_config`

- An optional configuration for the `tarpit` responder
- Config holds the tarpit responder`s configuration.
- Default: `{Headers: {}, timeout: 30s, ResponseCode: 200}`

`tarpit_config/headers`

- An optional configuration for the headers to be set with the tarpit config.
- Default: `{}`

`tarpit_config/timeout`

- A Duration represents the elapsed time between two instants as an int64 nanosecond count.
- The representation limits the largest representable duration to approximately 290 years.

`tarpit_config/bytes_per_second`

- An optional configuration for the default amount of bytes to stream per second.
- Default: `24`.

`tarpit_config/code`

- An optional configuration for the default response code for the tarpit responder.
- Default: `http.statusOK`

`serve_ignore`

- ServeIgnore specifies whether to serve a robots.txt file with a "Disallow: /" directive.
- Default: `false`

> _For code examples, check out [examples](examples.md)._

---

## **Embedded IP Ranges**

The plugin includes predefined IP ranges for popular AI services. These ranges are embedded in the binary and can be used without additional configuration.

|                               Service                                |                     Key                     |                                               IP Ranges (GitHub)                                               |
| :------------------------------------------------------------------: | :-----------------------------------------: | :------------------------------------------------------------------------------------------------------------: |
|                            Alibaba Cloud                             |                   aliyun                    |       [aliyun.go](https://github.com/JasonLovesDoggo/caddy-defender/blob/main/ranges/fetchers/aliyun.go)       |
|                                 VPNs                                 |                     vpn                     |          [vpn.go](https://github.com/JasonLovesDoggo/caddy-defender/blob/main/ranges/fetchers/vpn.go)          |
|                                 AWS                                  |                     aws                     |        [aws.go](https://github.com/JasonLovesDoggo/caddy-defender/blob/main/ranges/fetchers/aws/aws.go)        |
|                              AWS Region                              | aws-us-east-1, aws-us-west-1, aws-eu-west-1 | [aws_region.go](https://github.com/JasonLovesDoggo/caddy-defender/blob/main/ranges/fetchers/aws/aws_region.go) |
|                               DeepSeek                               |                  deepseek                   |     [deepseek.go](https://github.com/JasonLovesDoggo/caddy-defender/blob/main/ranges/fetchers/deepseek.go)     |
|                            GitHub Copilot                            |                githubcopilot                |       [github.go](https://github.com/JasonLovesDoggo/caddy-defender/blob/main/ranges/fetchers/github.go)       |
|                        Google Cloud Platform                         |                   gcloud                    |       [gcloud.go](https://github.com/JasonLovesDoggo/caddy-defender/blob/main/ranges/fetchers/gcloud.go)       |
|                     Oracle Cloud Infrastructure                      |                     oci                     |       [oracle.go](https://github.com/JasonLovesDoggo/caddy-defender/blob/main/ranges/fetchers/oracle.go)       |
|                           Microsoft Azure                            |              azurepubliccloud               |        [azure.go](https://github.com/JasonLovesDoggo/caddy-defender/blob/main/ranges/fetchers/azure.go)        |
|                                OpenAI                                |                   openai                    |       [openai.go](https://github.com/JasonLovesDoggo/caddy-defender/blob/main/ranges/fetchers/openai.go)       |
|                               Mistral                                |                   mistral                   |      [mistral.go](https://github.com/JasonLovesDoggo/caddy-defender/blob/main/ranges/fetchers/mistral.go)      |
|                                Vultr                                 |                    vultr                    |        [vultr.go](https://github.com/JasonLovesDoggo/caddy-defender/blob/main/ranges/fetchers/vultr.go)        |
|                              Cloudflare                              |                 cloudflare                  |   [cloudflare.go](https://github.com/JasonLovesDoggo/caddy-defender/blob/main/ranges/fetchers/cloudflare.go)   |
|                            Digital Ocean                             |                digitalocean                 | [digitalocean.go](https://github.com/JasonLovesDoggo/caddy-defender/blob/main/ranges/fetchers/digitalocean.go) |
|                                Linode                                |                   linode                    |       [linode.go](https://github.com/JasonLovesDoggo/caddy-defender/blob/main/ranges/fetchers/linode.go)       |
| [Private](https://caddyserver.com/docs/caddyfile/matchers#remote-ip) |                   private                   |      [private.go](https://github.com/JasonLovesDoggo/caddy-defender/blob/main/ranges/fetchers/private.go)      |
|                           All IP addresses                           |                     all                     |          [all.go](https://github.com/JasonLovesDoggo/caddy-defender/blob/main/ranges/fetchers/all.go)          |

### **Disabled by default (require manual inclusion at build time)**

|             Service             | Key |                                      IP Ranges (GitHub)                                      |
| :-----------------------------: | :-: | :------------------------------------------------------------------------------------------: |
|         Tor Exit Nodes          | tor | [tor.go](https://github.com/JasonLovesDoggo/caddy-defender/blob/main/ranges/fetchers/tor.go) |
| ASN (Autonomous System Numbers) | asn | [asn.go](https://github.com/JasonLovesDoggo/caddy-defender/blob/main/ranges/fetchers/asn.go) |

More are welcome! For a precompiled list, see the [embedded results](https://github.com/JasonLovesDoggo/caddy-defender/blob/main/ranges/data/generated.go).

## **Rate Limiting Configuration**

**Feature:** Match requests by IP range and apply rate limiting using [caddy-ratelimit](https://github.com/mholt/caddy-ratelimit).

### **Caddyfile Syntax**

```caddy
defender ratelimit {
    ranges <cidr_or_predefined...>
}

rate_limit {
    # Match requests marked by Defender
    match header X-Defender-RateLimit true

    # Rate limiting parameters
    rate  <requests-per-second>
    burst <burst-size>
    key   <rate-limit-key>
}
```

### **JSON Configuration**

```json
{
  "handler": "defender",
  "raw_responder": "ratelimit",
  "ranges": ["aws", "10.0.0.0/8"],
  "rate_limit_header": "X-Defender-RateLimit"
}
```

## **Custom Responder Examples**

### **Return 200 OK with Custom Message (Default)**

```caddy
example.com {
    defender custom {
        ranges openai aws
        message "Please contact support for API access"
    }
    respond "Hello World"
}
```

```json
{
  "handler": "defender",
  "raw_responder": "custom",
  "message": "Please contact support for API access",
  "ranges": ["openai", "aws"]
}
```

### **Return 403 Forbidden with Custom Message**

```caddy
example.com {
    defender custom {
        ranges openai aws
        message "You don't have permission to access this page"
        status_code 403
    }
    respond "Hello World"
}
```

```json
{
  "handler": "defender",
  "raw_responder": "custom",
  "message": "You don't have permission to access this page",
  "status_code": 403,
  "ranges": ["openai", "aws"]
}
```

### **Return 404 Not Found for Stealth Mode**

```caddy
example.com {
    defender custom {
        ranges vpn tor
        message "Page not found"
        status_code 404
    }
    respond "Hello World"
}
```

```json
{
  "handler": "defender",
  "raw_responder": "custom",
  "message": "Page not found",
  "status_code": 404,
  "ranges": ["vpn", "tor"]
}
```

### **Return 451 Unavailable For Legal Reasons**

```caddy
example.com {
    defender custom {
        ranges 192.168.1.0/24
        message "This content is not available in your region due to legal restrictions"
        status_code 451
    }
    respond "Hello World"
}
```

```json
{
  "handler": "defender",
  "raw_responder": "custom",
  "message": "This content is not available in your region due to legal restrictions",
  "status_code": 451,
  "ranges": ["192.168.1.0/24"]
}
```

### **Return 503 Service Unavailable for Maintenance**

```caddy
example.com {
    defender custom {
        ranges all
        message "Service temporarily unavailable for maintenance"
        status_code 503
    }
}
```

```json
{
  "handler": "defender",
  "raw_responder": "custom",
  "message": "Service temporarily unavailable for maintenance",
  "status_code": 503,
  "ranges": ["all"]
}
```

## **Example Configurations**

### **Basic Configuration**

```caddy
example.com {
    defender ratelimit {
        ranges cloudflare openai
    }

    rate_limit {
        match header X-Defender-RateLimit true
        rate  5r/s
        burst 10
        key   {http.request.remote.host}
    }

    respond "Hello World"
}
```

### **Advanced Configuration**

```caddy
api.example.com {
    defender ratelimit {
        ranges 192.168.1.0/24 azure
        rate_limit_header X-API-RateLimit
    }

    rate_limit {
        match header X-API-RateLimit true
        rate  10r/s
        burst 20
        key   {http.request.uri.path}

        # Optional: Custom response
        respond {
            status_code 429
            body "Too Many Requests - Try Again Later"
        }
    }

    reverse_proxy localhost:3000
}
```

## **Documentation**

### **Directives**

**Defender Rate Limit Responder:**

- `ranges` - IP ranges to apply rate limiting (CIDR or predefined)
- `rate_limit_header` (optional) - Header to mark requests for rate limiting (default: `X-Defender-RateLimit`)

**Rate Limit Module:**

- `match header` - Match the header set by Defender
- `rate` - Requests per second (e.g., `10r/s`)
- `burst` - Allow temporary bursts of requests
- `key` - Rate limit key (typically client IP or path)

### **How It Works**

1. **IP Matching:** Defender checks if client IP matches configured ranges
2. **Header Marking:** Matching requests get a header (`X-Defender-RateLimit: true`)
3. **Rate Limiting:** caddy-ratelimit applies limits only to marked requests
4. **Request Processing:** Non-matched requests bypass rate limiting

### **Use Cases**

- Protect API endpoints from scraping
- Mitigate brute force attacks
- Enforce different rate limits for:
  - Different geographic regions
  - Known bot networks
  - Internal vs external traffic

### **Requirements**

- [caddy-ratelimit](https://github.com/mholt/caddy-ratelimit) module installed
- [caddy-defender](https://github.com/JasonLovesDoggo/caddy-defender) v0.5.0+

### **Notes**

1. **Order Matters:** Defender must come before ratelimit in handler chain
2. **Header Customization:** Change header name if conflicts occur
3. **Combination with Other Protections:**

```caddy
defender ratelimit {
   ranges aws
}

rate_limit {
   match header X-Defender-RateLimit true
   rate 2r/s
}

defender block {
   ranges known-bad-ips
}
```

---

### **Troubleshooting**

1\. **Check Headers:**

```bash
curl -I http://example.com
```

2\. **Verify Handler Order:** Defender → Ratelimit → Other handlers

3\. **Test Rate Limits:**

```bash
# Simulate requests from blocked range
for i in {1..20}; do
   curl -H "X-Forwarded-For: 20.202.43.67" http://example.com
done
```
