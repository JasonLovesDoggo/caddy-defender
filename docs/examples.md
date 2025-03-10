#### **Responder Types**

Caddy Defender supports multiple response strategies:

| Responder   | Description                                                                         | Configuration Required         |
|-------------|-------------------------------------------------------------------------------------|--------------------------------|
| `block`     | Immediately blocks requests with 403 Forbidden                                      | No                             |
| `custom`    | Returns a custom text response                                                      | `message` field required       |
| `drop`      | Drops the connection                                                                | No                             |
| `garbage`   | Returns random garbage data to confuse scrapers/AI                                  | No                             |
| `ratelimit` | Marks requests for rate limiting (requires `caddy-ratelimit` integration)           | Additional rate limit config   |
| `redirect`  | Returns `308 Permanent Redirect` response                                           | `url` field required           |
| `tarpit`    | Stream data at a slow, but configurable rate to stall bots and pollute AI training. | `tarpit_config` block required |

---

# FOR FULL COMPLETE EXAMPLES, PLEASE CHECK OUT 
<a href="../examples"/>The Examples Folder



#### **Block Requests**

Block requests from specific IP ranges with 403 Forbidden:

```caddyfile
localhost:8080 {
    defender block {
        ranges 203.0.113.0/24 openai 198.51.100.0/24
    }
    respond "Human-friendly content"
}

# JSON equivalent
{
    "handler": "defender",
    "raw_responder": "block",
    "ranges": ["203.0.113.0/24", "openai"]
}
```

---

#### **Custom Response**

Return tailored messages for blocked requests:

```caddyfile
localhost:8080 {
    defender custom {
        ranges 10.0.0.0/8
        message "Access restricted for your network"
    }
    respond "Public content"
}

# JSON equivalent
{
    "handler": "defender",
    "raw_responder": "custom",
    "ranges": ["10.0.0.0/8"],
    "message": "Access restricted for your network"
}
```

---

#### **Drop connections**

Drop connections rather than send a response:

```caddyfile
localhost:8080 {
    defender drop {
        ranges 203.0.113.0/24 openai 198.51.100.0/24
    }
}

# JSON equivalent
{
    "handler": "defender",
    "raw_responder": "drop",
    "ranges": ["203.0.113.0/24", "openai"]
}
```

---

#### **Return Garbage Data**

Return meaningless content for AI/scrapers:

```caddyfile
localhost:8080 {
    defender garbage {
        ranges 192.168.0.0/24
    }
    respond "Legitimate content"
}

# JSON equivalent
{
    "handler": "defender",
    "raw_responder": "garbage",
    "ranges": ["192.168.0.0/24"]
}
```

---

#### **Rate Limiting**

Integrate with [caddy-ratelimit](https://github.com/mholt/caddy-ratelimit):

```caddyfile
{
	order rate_limit after basic_auth
}

:80 {
	defender ratelimit {
		ranges private
	}

	rate_limit {
		zone static_example {
			match {
				method GET
				header X-RateLimit-Apply true
			}
			key {remote_host}
			events 3
			window 1m
		}
	}

	respond "Hey I'm behind a rate limit!"
}
```

For complete rate limiting documentation,
see [RATELIMIT.md](./ratelimit.md) and [caddy-ratelimit](https://github.com/mholt/caddy-ratelimit).

---

#### **Redirect Response**

Redirect requests:

```caddyfile
localhost:8080 {
    defender redirect {
        ranges 10.0.0.0/8
        url "https://example.com"
    }
}

# JSON equivalent
{
    "handler": "defender",
    "raw_responder": "redirect",
    "ranges": ["10.0.0.0/8"],
    "url": "https://example.com"
}
```

---

#### **Tarpit**

Stream data at a slow, but configurable rate to stall bots and pollute AI training.

```caddyfile
localhost:8080 {
    defender tarpit {
        ranges private
        tarpit_config {
            # Optional headers
            headers {
                X-You-Got Played
            }
            # Optional. Use content from local file to stream slowly. Can also use source from http/https which is cached locally.
            content file://some-file.txt
            # Optional. Complete request at this duration if content EOF is not reached. Default 30s
            timeout 30s
            # Optional. Rate of data stream. Default 24
            bytes_per_second 24
            # Optional. HTTP Response Code Default 200
            response_code 200
        }
    }
}

# JSON equivalent
{
    "handler": "defender",
    "raw_responder": "tarpit",
    "ranges": ["10.0.0.0/8"],
    "tarpit_config": {
        "headers": {
             "X-You-Got" "Played"
        },
        "content": "file://some-file.txt",
        "timeout": "30s",
        "bytes_per_second": 24,
        "response_code": 200
    }
}
```

---

#### **Combination Example**

Mix multiple response strategies:
```caddyfile
example.com {
    defender block {
        ranges known-bad-actors
    }
    
    defender ratelimit {
        ranges aws
    }
    
    defender garbage {
        ranges scrapers
    }
    
    respond "Main Website Content"
}
```
