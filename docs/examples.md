#### **Responder Types**

Caddy Defender supports multiple response strategies:

| Responder   | Description                                                               | Configuration Required       |
|-------------|---------------------------------------------------------------------------|------------------------------|
| `block`     | Immediately blocks requests with 403 Forbidden                            | No                           |
| `garbage`   | Returns random garbage data to confuse scrapers/AI                        | No                           |
| `custom`    | Returns a custom text response                                            | `message` field required     |
| `ratelimit` | Marks requests for rate limiting (requires `caddy-ratelimit` integration) | Additional rate limit config |

---

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
