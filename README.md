# Hysteria Backend

A two-component system for managing Hysteria proxy authentication and traffic tracking.

```
                  +------------------+
                  |  Central Server  |
                  |   (SQLite DB)    |
                  +--------+---------+
                     ^           ^
       GET /server/  |           |  POST /server/
       config/{id}   |           |  status/{id}
          GET /auth  |           |  POST /traffic
                     |           |
         +-----------+--+   +----+-----------+
         |   Backend A  |   |   Backend B    |   ...
         | (per-node)   |   | (per-node)     |
         +------+-------+   +-------+--------+
                |                    |
         Hysteria Proxy A     Hysteria Proxy B
```

**Backend** (`cmd/backend`) runs on each Hysteria proxy node. It auto-installs Hysteria, fetches config from central, writes `/etc/hysteria/config.yaml`, manages the systemd service, handles auth decisions, kicks unauthorized users, and reports traffic and status.

**Central** (`cmd/central`) is a single management server. It stores users, server configs, server assignments, and aggregated traffic in SQLite. It provides a web dashboard for managing both users and servers.

## Building

```bash
go build -o backend ./cmd/backend/
go build -o central ./cmd/central/
```

## Setup

### 1. Start the Central Server

```bash
./central --listen :9090 --db central.db --base-url https://central.yundong.dev
```

| Flag         | Default      | Description                                          |
|--------------|--------------|------------------------------------------------------|
| `--listen`   | `:9090`      | Listen address                                       |
| `--db`       | `central.db` | SQLite database file path                            |
| `--debug`    | `false`      | Enable debug logging                                 |
| `--base-url` | (empty)      | Base URL for auto-filling auth_url/traffic_url fields |

The database and tables are created automatically on first run.

### 2. Add a Server Config

Create a server config entry via the admin API or dashboard:

```bash
curl -X POST http://localhost:9090/admin/servers/ \
  -H 'Content-Type: application/json' \
  -d '{
    "id": "srv1",
    "acme_domain": "p1.yundong.dev",
    "acme_email": "admin@yundong.dev"
  }'
```

If `auth_url` and `traffic_url` are left empty, the central server auto-fills them from `-base-url` (e.g. `https://central.yundong.dev/auth` and `https://central.yundong.dev/traffic`).

### 3. Add Users and Assign to Servers

```bash
# Add a user with a 10 GiB quota
curl -X POST http://localhost:9090/admin/users \
  -d '{"id":"alice", "quota": 10737418240}'

# Assign user to a server
curl -X POST http://localhost:9090/admin/servers/srv1/users \
  -d '{"id":"alice"}'
```

### 4. Start the Backend on Each Proxy Node

```bash
./backend \
  --server-id srv1 \
  --central-server https://central.yundong.dev
```

| Flag                             | Default | Description                                |
|----------------------------------|---------|--------------------------------------------|
| `--server-id`                    | (required) | Server identifier (must match central config) |
| `--central-server`              | (required) | Central server base URL                    |
| `--debug`                        | `false`    | Enable debug logging                       |
| `--interval-config-from-central` | `10s`      | How often to fetch config from central     |

All other config (ACME domain, intervals, auth/traffic URLs) is pulled from the central server via `GET /server/config/{server_id}`.

At startup, the backend will:
1. Generate a random 64-character secret for Hysteria traffic stats API
2. Generate random local ports (40000-49999) for the backend listen address and proxy stat API
3. Check if `hysteria` is installed; auto-install via `bash <(curl -fsSL https://get.hy2.sh/)` if not
4. Fetch config from central server
5. Write `/etc/hysteria/config.yaml` and restart `hysteria-server.service` (retry with new ports on conflict)
6. Start periodic goroutines for auth sync, kick checks, traffic collection, traffic reporting, status reporting, and config polling
7. Start the local auth HTTP server (retry with new port on conflict)

### 5. Reverse Proxy with Caddy (Recommended)

In production, put Caddy in front of the central server for automatic HTTPS and to protect the admin API with basic auth.

**a. Generate a password hash:**

```bash
caddy hash-password --plaintext YOUR_PASSWORD
```

**b. Edit the `Caddyfile`:**

Replace the hash after `admin` with the output from step (a).

```
{
    email admin@yundong.dev
}

central.yundong.dev {
    handle /admin/* {
        basicauth {
            admin $2a$14$...your-hash-here...
        }
        reverse_proxy localhost:9090
    }

    handle {
        reverse_proxy localhost:9090
    }
}
```

The `/auth/`, `/traffic/`, and `/server/` routes are left open (they are secured by the server_id and used by backend nodes).

**c. Start Caddy:**

```bash
caddy run                  # foreground
caddy start                # background (daemonized)
```

## Web Dashboard

Access the admin dashboard at `https://central.yundong.dev/admin/` (or `http://localhost:9090/admin/` locally).

The dashboard has two tabs:

- **Users** - View all users with TX/RX/Quota/Usage. Set/add quota, add/delete users, manage server assignments.
- **Servers** - View all servers with status, Hysteria version, uptime, last seen, and user count. Add/edit/delete server configs.

Server status badges:
- Green (online) - last seen within 60 seconds
- Yellow (recent) - last seen within 300 seconds
- Red (offline) - last seen more than 300 seconds ago or never

## How It Works

1. **Config sync** - The backend periodically fetches its config from the central server (`GET /server/config/{server_id}`). If Hysteria-relevant config changes (ACME domain, email), it rewrites `/etc/hysteria/config.yaml` and restarts the service. Interval changes take effect on the next cycle.

2. **Auth sync** - The backend periodically fetches the user list for its server from the central server (`GET /auth/{server_id}`). The central server only returns users who are assigned to the server **and** have not exceeded their traffic quota.

3. **Auth decisions** - When Hysteria asks if a client can connect, the backend checks the user's `auth` field against the cached list. Returns 200 if allowed, 403 if not.

4. **Kick enforcement** - The backend periodically checks who is online (`GET /online`), compares against the auth list, and kicks anyone not on it (`POST /kick`).

5. **Traffic collection** - The backend periodically fetches traffic stats from Hysteria (`GET /traffic?clear=1`) and accumulates them locally.

6. **Traffic reporting** - The backend periodically sends accumulated traffic to the central server (`POST /traffic/{server_id}`).

7. **Status reporting** - The backend periodically sends its status (active, Hysteria version, backend version, uptime) to the central server (`POST /server/status/{server_id}`).

8. **Quota enforcement** - Each user has a `quota` (total bytes for tx+rx combined). A quota of `0` means no access. Once their total traffic reaches the quota, they are excluded from the auth list.

## Admin API Reference

All admin endpoints are on the central server.

### Users

```bash
# List all users
curl http://localhost:9090/admin/users

# Add a user (quota=0 means no access until quota is set)
curl -X POST http://localhost:9090/admin/users -d '{"id":"alice"}'

# Add a user with a 10 GiB quota
curl -X POST http://localhost:9090/admin/users -d '{"id":"alice", "quota": 10737418240}'

# Delete a user (cascades to server assignments and traffic)
curl -X DELETE http://localhost:9090/admin/users/alice
```

### Servers

```bash
# List all server configs
curl http://localhost:9090/admin/servers/

# Create a server
curl -X POST http://localhost:9090/admin/servers/ \
  -H 'Content-Type: application/json' \
  -d '{
    "id": "srv1",
    "acme_domain": "p1.yundong.dev",
    "acme_email": "admin@yundong.dev"
  }'

# Get a server's config
curl http://localhost:9090/admin/servers/srv1

# Update a server's config
curl -X PUT http://localhost:9090/admin/servers/srv1 \
  -H 'Content-Type: application/json' \
  -d '{"acme_domain": "p2.yundong.dev", "acme_email": "admin@yundong.dev"}'

# Delete a server
curl -X DELETE http://localhost:9090/admin/servers/srv1

# Get server overview (config + status + user count for all servers)
curl http://localhost:9090/admin/server-overview
```

### Server User Assignments

```bash
# List users assigned to a server
curl http://localhost:9090/admin/servers/srv1/users

# Assign a user to a server
curl -X POST http://localhost:9090/admin/servers/srv1/users -d '{"id":"alice"}'

# Unassign a user from a server
curl -X DELETE http://localhost:9090/admin/servers/srv1/users/alice
```

### Quota

Each user has a `quota` (bytes). `0` = no access. Users must have a positive quota to connect.

```bash
# Get a user's quota and current usage
curl http://localhost:9090/admin/quota/alice
# Response: {"quota": 10737418240, "used": 5368709120}

# Set a user's quota to 10 GiB (absolute)
curl -X PUT http://localhost:9090/admin/quota/alice \
  -d '{"quota": 10737418240}'

# Add 1 GiB to a user's quota
curl -X PATCH http://localhost:9090/admin/quota/alice \
  -d '{"delta": 1073741824}'

# Block a user (set quota to 0)
curl -X PUT http://localhost:9090/admin/quota/alice \
  -d '{"quota": 0}'
```

### Traffic

```bash
# View all user traffic (aggregated across all servers)
curl http://localhost:9090/admin/traffic

# View traffic for a specific user
curl http://localhost:9090/admin/traffic/alice
```

### Backend-Facing Endpoints

These are called by backend nodes (not admin-protected):

```bash
# Get server config (called by backend at startup and periodically)
curl http://localhost:9090/server/config/srv1

# Post server status (called by backend periodically)
curl -X POST http://localhost:9090/server/status/srv1 \
  -H 'Content-Type: application/json' \
  -d '{"status":"active","hysteria_version":"v2.x.x","backend_version":"2.0.0","uptime_seconds":3600}'
```
