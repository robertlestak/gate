# gate

`gate` is a security-conscious SNI-aware TLS reverse proxy with a focus on upstream anonymity and self-service configuration.

`gate` is intended to be used in environments where "conventional" WAF providers, reverse proxies, and load balancers are not available or are otherwise undesirable due to security or cost concerns.

## Architecture

In a conventional L4 sense, `gate` operates similarly to other proxy solutions such as NGINX and HAProxy. However whereas these services require central configuration by an operations team, `gate` is designed to operate in a self-service manner. `gate` can be run in two modes: `server` or `upstream`. 

`gate` servers sit at the edge of a network and accept incoming connections from end-users and route them to the appropriate upstream service. `gate` uses SNI to determine the upstream service to route to, meaning that you do _not_ need to load TLS private keys into the `gate` server, as you would have to do with L7 proxies. Traffic is encrypted end-to-end between the end-user and the upstream service, and `gate` does not have access to the plaintext traffic (outside of the SNI header used to select the respective upstream service).

`gate` upstreams are the services that `gate` routes traffic to. Upstreams must present a valid TLS certificate for the SNI hostname that `gate` is configured to route to, and must accept incoming connections from `gate` on the configured port (default 443). Upstreams can be any service that accepts TLS connections, including HTTP, SSH, and other TCP-based services.

Once an `upstream` is registered with a `gate` server, you can update your DNS to point the SNI hostname to the `gate` server, and `gate` will route traffic to the upstream service. Clients will see the upstream service's TLS certificate, and will not be aware that `gate` is in the middle unless they trace the connection. Since `gate` acts as a L4 reverse proxy, a `traceroute` will not reveal the upstream service behind the `gate` server.

## Usage

### Server

The `server` mode is used to accept incoming connections from end-users and route them to the appropriate upstream service. `gate` servers are intended to be run at the edge of the network, and should be configured to accept incoming connections on port 443 and port 80 (for HTTP->HTTPS redirects), as well as port 4443 for upstream/server communication.

You must have a TLS cert and key for your gate server to secure upstream-server communication. While there is _technically_ a way to start gate without TLS, that would largely defeat the purpose of `gate` and so that will not be covered here. In addition to server-side TLS, you can optionally require mTLS for upstream/server communication. This is recommended, but not required, as it does add some additional complexity to the setup around PKI and certificate management.

#### Server Configuration

At the bare minimum, you can start a gate server with the defaults, just providing a TLS cert and key:

```bash
gate server \
    -tls-cert /path/to/tls.crt \
    -tls-key /path/to/tls.key
```

This will start a gate server listening on ports 443, 80, and 4443, with no upstreams configured. 

As no private key has been provided to encrypt the memory, the server will prompt you to enter a private key. This key will be used to encrypt the memory used to store the upstreams and other configuration, so that in the event the environment hosting the `gate` server is compromised, the attacker will not be able to read the configuration and read upstream hostnames and addresses. You will need to provide this key every time you start the server, so make sure to store it somewhere safe. You can optionally provide the key file via the `-memory-key` flag. If this is done, it's recommended to use a key file that is encrypted at rest, such as a GPG-encrypted file, or pass the `-memory-rm-key` flag to remove the key file from the server after it has been loaded into memory. Finally, you can provide an environment variable `MEMORY_KEY` with the key value, and `gate` will read it from there. See the [Memory Encryption](#memory-encryption) section for more details.

Any client with netpath access to the management port (4443) will be able to register upstreams with the server. This can be restricted either with mTLS (`-tls-client-auth`), or with a registration key that must be provided by the client (`-registration-key`).

##### Upstream Configuration

Once your `gate` server is up and running, you can register upstreams with it. Upstream registration is done over a TLS-encrypted TCP connection to the management port (4443).

`gate` upstream registration does not need to be done on the actual upstream server, enabling you to decouple the upstream registration from the upstream service itself. This is useful in situations where you may not have direct access to the upstream server, or where you want to register multiple upstreams with a single `gate` server (or vice versa, a single upstream with multiple `gate` servers for redundancy).

Before registering an upstream, it must be up and running, and configured to accept incoming connections from the `gate` server. The upstream must also present a valid TLS certificate for the SNI hostname that `gate` will be routing to. When registering, the connection will be tested to ensure that the upstream is reachable and that the TLS certificate is valid.

To register an upstream, you must provide the external-facing hostname that the upstream will be accessed via, the internal hostname / IP that `gate` will connect to, and a key to sign and secure messages between the `upstream` and `server`.

```bash
gate upstream \
    -gate gate.example.com:4443 \
    -key /path/to/key.pem \
    -external mycoolapp.com \
    -internal mycoolapp.internal \
    register
```

This will register the upstream with the `gate` server, and the upstream will be available for routing traffic to. You can register as many upstreams as you want with a single `gate` server. To remove an upstream, use the `deregister` command:

```bash
gate upstream \
    -gate gate.example.com:4443 \
    -key /path/to/key.pem \
    -external mycoolapp.com \
    -internal mycoolapp.internal \
    deregister
```

By default, requests exceeding 5 minutes will be timed out at the server. This can be configured with the `-timeout` flag, which accepts a duration string. For example, to set the timeout to 10 minutes:

```bash
gate upstream \
    -gate gate.example.com:4443 \
    -key /path/to/key.pem \
    -external mycoolapp.com \
    -internal mycoolapp.internal \
    -timeout 10m \
    register
```

You can also set a rate limit on the upstream, which will limit the number of requests per second that the upstream will accept. This can be useful to prevent DDoS attacks against the upstream. To set a rate limit of 100 requests per second:

```bash
gate upstream \
    -gate gate.example.com:4443 \
    -key /path/to/key.pem \
    -external mycoolapp.com \
    -internal mycoolapp.internal \
    -rate-limit 100 \
    register
```

By default, `gate` will allow all requests to the upstream. You can optionally provide a list of CIDR blocks to explicitly allow or deny access to the upstream. If the `-allow-cidrs` flag is provided, the `default ALLOW` will change to `default DENY` and only requests from the provided CIDR blocks will be allowed. If the `-deny-cidrs` flag is provided, the `default ALLOW` will remain, and only requests from the provided CIDR blocks will be denied. If used together, the `-allow-cidrs` flag will take precedence.

```bash
gate upstream \
    -gate gate.example.com:4443 \
    -key /path/to/key.pem \
    -external mycoolapp.com \
    -internal mycoolapp.internal \
    -allow-cidrs "1.2.3.4/32,5.6.7.8/16" \
    register
```

You can update the upstream configuration in-place at any time by re-registering the upstream with the same external hostname. This will overwrite the existing upstream configuration. If you want to change the external hostname, you will need to deregister the upstream and re-register it with the new hostname.

###### Upstream Configuration File

To enable easier looping over multiple upstreams, you can provide a YAML file with the upstream configuration. The file should be formatted as follows:

```yaml
keyFile: /path/to/key.pem
upstream:
  external: "mycoolapp.com"
  internal: "mycoolapp.internal"
  timeout: "10s"
  rateLimit: 100
gate:
  server: "gate.example.com:4443"
  registrationKey: "${REGISTRATION_KEY}"
  tls:
    ca: /path/to/ca.crt
    cert: /path/to/tls.crt
    key: /path/to/tls.key
    insecure: false
```

This can be provided to the `upstream` command with the `-config` flag:

```bash
gate upstream \
    -config /path/to/config.yaml \
    register
```

## Memory Encryption

`gate` is intended to be run as a public-private gateway, and as such, it is likely that the server will be running in an environment that is not fully trusted. To mitigate the risk of an attacker gaining access to the server and reading the upstream configuration and finding the internal IP addresses of the upstreams to target more directly, `gate` encrypts the memory used to store the upstream configuration. This means that if an attacker gains access to the server, they will not be able to read the upstream configuration without the encryption key.

Under the hood, this uses the [memory](https://github.com/robertlestak/memory) library. The memory encryption key can be provided in one of four ways:

- Via the `-memory-key` flag
- Via the `MEMORY_KEY` environment variable
- As TTY input when starting the server
- Dynamically generated at start up with the `-memory-gen-key` flag

If the key is provided as a TTY input and the server restarts, you will need to provide the key again. If you use the `-memory-gen-key` flag, a new random key will be generated for the duration of that process. This does mean that if you use persistent `memory` backend such as `redis`, the data will become inaccessible if the server restarts and will need to be recreated. This is by design, as it is intended to be used in environments where the server is not trusted, and so the data should not be persisted.

## When to use `gate`

In certain situations, you may not want to - or be able to - use conventional WAF / proxy providers such as Cloudflare, Akamai, or AWS. This could be due to cost, security, or other concerns. At the same time, your use case does not warrant - or prevents you - from using [TOR Onion Services](https://community.torproject.org/onion-services/).

TOR Onion Services are a great solution for providing complete anonymity and security, but they do have some drawbacks. For example, they require the use of the TOR Browser, which is not always feasible. They also require the use of the TOR network, which can be slower than expected for "conventional" internet users. Finally, they require the use of a `.onion` domain, which may not be desirable for branding purposes.

In cases where you would like to take advantage of "conventional internet infrastructure" while still adding a tangible layer of security and anonymity, `gate` can be a good solution. It is not a replacement for TOR Onion Services, but it can be a good alternative in certain situations.

If someone were able to compromise the `gate` server, while they would not be able to read the encrypted upstream configuration details, they would be able to monitor the local network interface and correlate incoming connections to outbound TCP connections, which would reveal the upstream IP address. To mitigate this, additional reverse proxy layers can be added to the upstream behind the `gate` server, which would make it more difficult to correlate the incoming connections to the upstream. This is left as an exercise for the reader. At the end of the day, if you are concerned about this level of attack, you should be using TOR Onion Services instead.