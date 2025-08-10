# Advanced Usage

This section provides guidance on advanced configuration options for the Caddy Defender plugin, including how to enable and customize features that require manual steps at build time.

## Enabling Build-Time IP Range Fetchers

Some IP range fetchers, such as those for **Tor exit nodes** and **ASN (Autonomous System Numbers)**, are not enabled by default in the standard build. This is because they can have a significant impact on performance or require user-specific configuration.

To use these fetchers, you need to build a custom version of the Caddy binary with the desired features enabled. This is done by running a Go program that generates the IP range data, and then building the plugin with `xcaddy`.

### Step 1: Prepare Your Environment

Ensure you have a working Go environment and `xcaddy` installed.

- [Install Go](https://golang.org/doc/install)
- [Install `xcaddy`](https://github.com/caddyserver/xcaddy)

### Step 2: Run the IP Range Generator

The Caddy Defender plugin includes a Go program at `ranges/main.go` that fetches IP ranges and generates a Go file (`ranges/data/generated.go`) containing this data. You can enable the Tor and ASN fetchers using command-line flags.

#### Enabling the Tor Fetcher

To enable the Tor fetcher, use the `--fetch-tor` flag:

```bash
go run ranges/main.go --fetch-tor
```

This will regenerate the `ranges/data/generated.go` file with the Tor exit node IP ranges included under the `tor` key.

#### Enabling the ASN Fetcher

To enable the ASN fetcher, use the `--asn` flag with a comma-separated list of ASNs you want to block. For example, to block Google (AS15169) and Cloudflare (AS13335), run:

```bash
go run ranges/main.go --asn "AS15169,AS13335"
```

This will add the IP ranges for the specified ASNs to the `asn` key in the generated data file.

You can combine flags to enable multiple fetchers at once:

```bash
go run ranges/main.go --fetch-tor --asn "AS15169"
```

### Step 3: Build Caddy with `xcaddy`

After generating the `generated.go` file, you can build your custom Caddy binary:

```bash
xcaddy build --with pkg.jsn.cam/caddy-defender
```

This will create a `caddy` executable in your current directory that includes the custom IP range data.

### Using in Docker

If you build your Caddy image using Docker, you can add these steps to your `Dockerfile`. Here is an example `Dockerfile` that enables the Tor and ASN fetchers:

```dockerfile
FROM caddy:2-builder AS builder

# Clone the Caddy Defender repository
RUN go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
WORKDIR /app
RUN git clone https://github.com/JasonLovesDoggo/caddy-defender.git

# Run the IP range generator with your desired options
WORKDIR /app/caddy-defender
RUN go run ranges/main.go --fetch-tor --asn "AS15169"

# Build the Caddy binary with the custom data
RUN xcaddy build --with pkg.jsn.cam/caddy-defender

# Create the final image
FROM caddy:2
COPY --from=builder /app/caddy-defender/caddy /usr/bin/caddy
```

Now you can build and run this Docker image, and the `tor` and `asn` keys will be available for use in your `Caddyfile`.
