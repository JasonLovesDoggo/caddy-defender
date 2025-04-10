# **Installation**

## **Using Docker**

The easiest way to use the Caddy Defender plugin is by using the pre-built Docker image.

1\. **Pull the Docker Image**:

```bash
docker pull ghcr.io/jasonlovesdoggo/caddy-defender:latest
```

2\. **Run the Container**:
Use the following command to run the container with your `Caddyfile`:

```bash
docker run -d \
 --name caddy \
 -v /path/to/Caddyfile:/etc/caddy/Caddyfile \
 -p 80:80 -p 443:443 \
 ghcr.io/jasonlovesdoggo/caddy-defender:latest
```

Replace `/path/to/Caddyfile` with the path to your `Caddyfile`.

---

## **Using `xcaddy`**

You can also build Caddy with the Caddy Defender plugin using [`xcaddy`](https://github.com/caddyserver/xcaddy), a tool for building custom Caddy binaries.

1\. **Install `xcaddy`**:

```bash
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
```

2\. **Build Caddy with the Plugin**:
Run the following command to build Caddy with the Caddy Defender plugin:

```bash
xcaddy build --with github.com/jasonlovesdoggo/caddy-defender
```

This will produce a `caddy` binary in the current directory.

3\. **Run Caddy**:
Use the built binary to run Caddy with your configuration:

```bash
./caddy run --config Caddyfile
```

---

## **Download Binary Executable**

You can download Caddy along with the Caddy Defender Plugin pre-installed in the binary by [downloading it from their site here and clicking download](https://caddyserver.com/download?package=github.com%2Fjasonlovesdoggo%2Fcaddy-defender).
