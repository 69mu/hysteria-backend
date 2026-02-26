# Hysteria Backend

A two-component system for managing Hysteria proxy authentication and traffic tracking.

```
                  +------------------+
                  |  Central Server  |
                  |   (SQLite DB)    |
                  +--------+---------+
                     ^           ^
          GET /auth  |           |  POST /traffic
                     |           |
         +-----------+--+   +----+-----------+
         |   Backend A  |   |   Backend B    |   ...
         | (per-node)   |   | (per-node)     |
         +------+-------+   +-------+--------+
                |                    |
         Hysteria Proxy A     Hysteria Proxy B
```

**Backend** (`cmd/backend`) runs on each Hysteria proxy node. It handles auth decisions, kicks unauthorized users, and collects traffic stats.

**Central** (`cmd/central`) is a single management server. It stores users, server assignments, and aggregated traffic in SQLite.

## Building

```bash
go build -o backend ./cmd/backend/
go build -o central ./cmd/central/
```

## Setup

### 1. Start the Central Server

```bash
./central --listen :9090 --db central.db
```

| Flag       | Default      | Description               |
|------------|--------------|---------------------------|
| `--listen` | `:9090`      | Listen address            |
| `--db`     | `central.db` | SQLite database file path |

The database and tables are created automatically on first run.

### 2. Add Users and Assign to Servers

Each proxy node is identified by a high-entropy `server_id` (acts as both identifier and secret).

```bash
# Add a user
curl -X POST http://localhost:9090/admin/users \
  -d '{"id":"alice"}'

curl -X POST http://localhost:9090/admin/users \
  -d '{"id":"bob"}'

# Assign users to a server (use a long random string as server_id)
SERVER_ID="x7k9m2p4q8r1w5"

curl -X POST http://localhost:9090/admin/servers/$SERVER_ID/users \
  -d '{"id":"alice"}'

curl -X POST http://localhost:9090/admin/servers/$SERVER_ID/users \
  -d '{"id":"bob"}'
```

### 3. Start the Backend on Each Proxy Node

```bash
./backend \
  --server-id x7k9m2p4q8r1w5 \
  --central-server-auth http://central-host:9090/auth \
  --central-server-traffic http://central-host:9090/traffic \
  --proxy-server 127.0.0.1:9000 \
  --secret your-hysteria-api-secret \
  --listen :8080
```

| Flag                           | Default         | Description                                      |
|--------------------------------|-----------------|--------------------------------------------------|
| `--server-id`                  | (required)      | This node's server ID (must match central config) |
| `--central-server-auth`       | (required)      | Central server auth URL                          |
| `--central-server-traffic`    | (required)      | Central server traffic URL                       |
| `--proxy-server`              | `127.0.0.1:9000`| Hysteria proxy API address                       |
| `--traffic-server`            | `127.0.0.1:9000`| Hysteria traffic API address                     |
| `--secret`                    | `abcdefg`       | Hysteria API secret                              |
| `--listen`                    | `:8080`         | Local auth API listen address                    |
| `--interval-auth`             | `10s`           | How often to refresh the auth list               |
| `--interval-kick`             | `10s`           | How often to check and kick unauthorized users   |
| `--interval-traffic-from-proxy`| `10s`          | How often to fetch traffic from Hysteria         |
| `--interval-traffic-to-central`| `10s`          | How often to report traffic to central           |

### 4. Configure Hysteria to Use the Backend

In your Hysteria server config, point HTTP authentication at the backend:

```yaml
auth:
  type: http
  http:
    url: http://127.0.0.1:8080/
```

And enable the traffic stats API:

```yaml
trafficStats:
  listen: :9000
  secret: your-hysteria-api-secret
```

## How It Works

1. **Auth sync** - The backend periodically fetches the user list for its `server_id` from the central server (`GET /auth/{server_id}`).

2. **Auth decisions** - When Hysteria asks if a client can connect, the backend checks the user's `auth` field against the cached list. Returns 200 if allowed, 403 if not.

3. **Kick enforcement** - The backend periodically checks who is online (`GET /online`), compares against the auth list, and kicks anyone not on it (`POST /kick`).

4. **Traffic collection** - The backend periodically fetches traffic stats from Hysteria (`GET /traffic?clear=1`) and accumulates them locally.

5. **Traffic reporting** - The backend periodically sends accumulated traffic to the central server (`POST /traffic/{server_id}`). The central server aggregates per-user totals across all nodes (e.g., if alice uses servers A, B, and C, only one total is stored).

## Admin API Reference

All admin endpoints are on the central server.

### Users

```bash
# List all users
curl http://localhost:9090/admin/users

# Add a user
curl -X POST http://localhost:9090/admin/users -d '{"id":"alice"}'

# Delete a user (cascades to server assignments and traffic)
curl -X DELETE http://localhost:9090/admin/users/alice
```

### Server Assignments

```bash
# List users assigned to a server
curl http://localhost:9090/admin/servers/SERVER_ID/users

# Assign a user to a server
curl -X POST http://localhost:9090/admin/servers/SERVER_ID/users -d '{"id":"alice"}'

# Unassign a user from a server
curl -X DELETE http://localhost:9090/admin/servers/SERVER_ID/users/alice
```

### Traffic

```bash
# View all user traffic (aggregated across all servers)
curl http://localhost:9090/admin/traffic

# View traffic for a specific user
curl http://localhost:9090/admin/traffic/alice
```

Response format:
```json
{
  "alice": {"tx": 123456, "rx": 789012},
  "bob":   {"tx": 456789, "rx": 123456}
}
```
