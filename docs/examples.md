# **Examples**

This part of the documentation contains usable examples which you can refer to when writing your caddyfile(s).

## **Responder Types**

Caddy Defender supports multiple response strategies:

| Responder   | Description                                                                         | Configuration Required         |
| ----------- | ----------------------------------------------------------------------------------- | ------------------------------ |
| `block`     | Immediately blocks requests with 403 Forbidden                                      | No                             |
| `custom`    | Returns a custom text response                                                      | `message` field required       |
| `drop`      | Drops the connection                                                                | No                             |
| `garbage`   | Returns random garbage data to confuse scrapers/AI                                  | No                             |
| `ratelimit` | Marks requests for rate limiting (requires `caddy-ratelimit` integration)           | Additional rate limit config   |
| `redirect`  | Returns `308 Permanent Redirect` response                                           | `url` field required           |
| `tarpit`    | Stream data at a slow, but configurable rate to stall bots and pollute AI training. | `tarpit_config` block required |

---

## **Block Requests**

Block requests from specific IP ranges with 403 Forbidden:

### **Example 1**

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

### **Example 2**

```caddyfile
{
	auto_https off
	order defender after header
	debug
}

:80 {
	bind 127.0.0.1 ::1

	defender block {
		ranges private
	}
	respond "This is what a human sees"
}

:83 {
	bind 127.0.0.1 ::1
	respond "Clear text HTTP"
}
```

---

## **Custom Response**

Return tailored messages for blocked requests:

### **Example 1**

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

### **Example 2**

```caddyfile
{
	auto_https off
	order defender after header
	debug
}

:80 {
	bind 127.0.0.1 ::1

	defender custom {
		ranges private
		message "You are not welcome here"
	}
	respond "This is what a human sees"
}

:83 {
	bind 127.0.0.1 ::1

	respond "Clear text HTTP"
}
```

---

## **Drop connections**

Drop connections rather than send a response:

### **Example 1**

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

### **Example 2**

```caddyfile
{
	auto_https off
	order defender after header
	debug
}

:80 {
	bind 127.0.0.1 ::1

	defender drop {
		ranges private
	}
}
```

---

## **Return Garbage Data**

Return meaningless content for AI/scrapers:

### **Example 1**

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

### **Example 2**

```caddyfile
{
	auto_https off
	order defender after header
	debug
}

:80 {
	bind 127.0.0.1 ::1

	defender garbage {
		ranges private
    	serve_ignore
	}
	respond "This is what a human sees"
}

:83 {
	bind 127.0.0.1 ::1

	respond "Clear text HTTP"
}
```

---

## **Rate Limiting**

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
see [Rate Limiting Configuration](config.md#rate-limiting-configuration) and [caddy-ratelimit](https://github.com/mholt/caddy-ratelimit).

---

## **Redirect Response**

Redirect requests:

### **Example 1**

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

### **Example 2**

```caddyfile
{
	auto_https off
	order defender after header
	debug
}

:80 {
	bind 127.0.0.1 ::1

	defender redirect {
		ranges private
		url "https://example.com"
	}
}
```

---

## **Tarpit**

Stream data at a slow, but configurable rate to stall bots and pollute AI training.

### **Example 1**

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

### **Example 2**

```caddyfile
{
	auto_https off
	order defender after header
	debug
}

:80 {
	bind 127.0.0.1 ::1

	defender tarpit {
		ranges private
        tarpit_config {
            # Optional headers
            headers {
                X-You-Got "Played"
            }
            # Optional. Use content from local file to stream slowly. Can also use source from http/https which is cached locally.
            # content file://some-file.txt
            content https://www.cloudflare.com/robots.txt
            # Optional. Complete request at this duration if content EOF is not reached. Default 30s
            timeout 30s
            # Optional. Rate of data stream. Default 24
            bytes_per_second 24
            # Optional. HTTP Response Code Default 200
            response_code 200
        }
    }
}
```

---

## **Combination Example**

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

---

## **Whitelisting**

Whitelist certain IP(s) from blocked ranges:

```caddyfile
{
	auto_https off
	order defender after header
	debug
}

:80 {
	bind 127.0.0.1 ::1
	# Everything in AWS besides my EC2 instance is blocked from accessing this site.
	defender block {
		ranges aws
		whitelist 169.254.169.254 # my ec2's public IP.
	}
	respond "This is what a human sees"
}

:81 {
	bind 127.0.0.1 ::1
	# My localhost ipv6 is blocked but not my ipv4
	defender block {
		ranges private
		whitelist 127.0.0.1
	}
	respond "This is what a ipv4 human sees"
}
```

---

## **File-Based Blocklist**

Load IP addresses/ranges from a file that's automatically monitored for changes:

### **Example 1 - Simple File Blocklist**

```caddyfile
localhost:8080 {
    defender block {
        blocklist_file /etc/caddy/blocklist.txt
    }
    respond "Legitimate content"
}
```

Create `/etc/caddy/blocklist.txt`:
```
# Blocked IP addresses and ranges
203.0.113.45
198.51.100.0/24
192.0.2.10

# Comments and empty lines are ignored
10.0.0.0/8
```

### **Example 2 - Combined with Predefined Ranges**

```caddyfile
{
    auto_https off
    order defender after header
}

:80 {
    defender block {
        ranges openai deepseek githubcopilot
        blocklist_file /etc/caddy/custom-blocks.txt
    }
    respond "This is what a human sees"
}
```

### **Example 3 - Docker Volume Mount**

In your `docker-compose.yml`:
```yaml
version: '3'
services:
  caddy:
    image: ghcr.io/jasonlovesdoggo/caddy-defender:latest
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile
      - ./blocklist.txt:/etc/caddy/blocklist.txt:ro
    restart: unless-stopped
```

Your `Caddyfile`:
```caddyfile
example.com {
    defender block {
        ranges openai aws
        blocklist_file /etc/caddy/blocklist.txt
    }
    reverse_proxy backend:8080
}
```

Your `blocklist.txt`:
```
# Dynamic blocklist - edit this file and Caddy will reload automatically
192.168.1.100
10.20.30.0/24
```

**Features:**
- File is monitored for changes and automatically reloaded
- No restart required when adding/removing IPs
- Lines starting with `#` are treated as comments
- Empty lines are ignored
- Supports both individual IPs and CIDR ranges
- IP addresses are validated on load (invalid entries logged as warnings)

---

## **geoip**

> _See issue [#27](https://github.com/JasonLovesDoggo/caddy-defender/issues/27)._

From [caddy-maxmind-geolocation](https://github.com/porech/caddy-maxmind-geolocation):

```caddyfile
localhost:8080 {
  @mygeofilter {
    maxmind_geolocation {
      db_path "/usr/share/GeoIP/GeoLite2-Country.mmdb"
      allow_countries IT FR # Allow access to the website only from Italy and France
    }
  }

   file_server @mygeofilter {
     root /var/www/html
   }
}
```
