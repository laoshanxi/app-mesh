# Secure consul cluster

Consul master running on 3 nodes, 2 separate Consul client(agent) running 2 nodes.

## Start the Services

### Generate a Valid Gossip Encryption Key

You need to generate a valid Base64-encoded gossip key using the Consul CLI. Run the following command to generate the key:

```bash
docker run -ti hashicorp/consul consul keygen
```

### Start the Consul cluster

```bash
cd script/consul/
docker-compose -f consul-service.yml up -d
```

## Verify the Setup

Visit the Consul UI at http://<server1-ip>:8500 (or whichever server you exposed) and check the Nodes tab. You should see the 3 servers (server1, server2, server3) and the 2 agents (agent1, agent2) listed.
Alternatively, you can use the Consul CLI on any of the servers or agents to verify that all nodes are connected:

```bash
consul members
```

This should list all 5 nodes (3 servers and 2 agents).

## Clean Up

When you're done with the setup, you can stop and remove the containers and networks for each service:

```bash
docker-compose -f consul-service.yml down
```

## Configuration

Consul configuration can be changed from file `/opt/appmesh/work/config/consul-api-config.yaml` or from environment variable:

```bash
export APPMESH_CONSUL_ENABLE=true
export APPMESH_CONSUL_ADDRESS="192.168.1.1:8500"
export APPMESH_CONSUL_TLS_CA_FILE="/new/path/to/ca.pem"
```
