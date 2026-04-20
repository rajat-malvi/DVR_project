import socket
import json
import threading
import time
import os
import subprocess
import pprint

pp = pprint.PrettyPrinter(indent=2)

MY_IP            = os.getenv("MY_IP", "127.0.0.1")
NEIGHBORS        = [n for n in os.getenv("NEIGHBORS", "").split(",") if n.strip()]
ROUTER_ID        = os.getenv("ROUTER_ID", MY_IP)
PORT             = 5000
UPDATE_INTERVAL  = 5
ROUTE_TIMEOUT    = 18
INFINITY         = 16
PROTOCOL_VERSION = 1.0

routing_table     = {}
table_lock        = threading.Lock()
local_subnets_set = set()

def init_routing_table():
    global local_subnets_set
    subnets = get_local_subnets()
    local_subnets_set = set(subnets)

    with table_lock:
        for subnet in subnets:
            routing_table[subnet] = {
                "distance": 0,
                "next_hop": "0.0.0.0",
                "last_updated": time.time()
            }

    print("\n[INIT] Router Started")
    print(f"Router ID : {ROUTER_ID}")
    print(f"My IP     : {MY_IP}")
    print(f"Neighbors : {NEIGHBORS}")
    print(f"Subnets   : {subnets}")
    print_table()


# SUBNET DETECTION
def get_local_subnets():
    subnets = []
    try:
        result = subprocess.run(
            ["ip", "-o", "-f", "inet", "addr", "show"],
            capture_output=True, text=True
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[2] == "inet":
                subnet = addr_to_network(parts[3])
                if subnet and not subnet.startswith("127."):
                    subnets.append(subnet)
    except:
        print("[WARN] Could not detect subnets")
    return list(set(subnets))

def addr_to_network(addr_prefix):
    try:
        ip_str, prefix = addr_prefix.split("/")
        prefix = int(prefix)
        ip_parts = list(map(int, ip_str.split(".")))
        mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        net = [(ip_parts[i] & ((mask >> (24 - 8 * i)) & 0xFF)) for i in range(4)]
        return f"{net[0]}.{net[1]}.{net[2]}.{net[3]}/{prefix}"
    except:
        return None


# BROADCAST
def broadcast_updates():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    while True:
        time.sleep(UPDATE_INTERVAL)

        with table_lock:
            snapshot = dict(routing_table)

        for neighbor_ip in NEIGHBORS:
            routes = []

            for subnet, info in snapshot.items():
                if info["next_hop"] == neighbor_ip:
                    dist = INFINITY
                else:
                    dist = info["distance"]

                routes.append({"subnet": subnet, "distance": dist})

            packet = {
                "router_id": MY_IP,
                "version": PROTOCOL_VERSION,
                "routes": routes
            }

            print(f"\n[SENDING UPDATE] To {neighbor_ip}")
            pp.pprint(packet)

            try:
                sock.sendto(json.dumps(packet).encode(), (neighbor_ip, PORT))
            except:
                print(f"[SEND ERROR] {neighbor_ip}")


# LISTEN
def listen_for_updates():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", PORT))

    print(f"\n[LISTENING] on port {PORT}")

    while True:
        try:
            data, addr = sock.recvfrom(65535)
            sender_ip = addr[0]
            packet = json.loads(data.decode())

            print("\n[RECEIVED PACKET]")
            print(f"From: {sender_ip}")
            pp.pprint(packet)

            if packet.get("version") != PROTOCOL_VERSION:
                continue

            update_logic(sender_ip, packet.get("routes", []))

        except:
            print("[ERROR] Receiving")


# BELLMAN-FORD
def update_logic(neighbor_ip, routes):
    changed = False

    with table_lock:
        for route in routes:
            subnet = route.get("subnet")
            rcv_dist = route.get("distance")

            if not subnet or rcv_dist is None:
                continue

            # allow updates but protect direct routes from overwrite
            if subnet in local_subnets_set:
                current = routing_table.get(subnet)
                
                # only ignore if it's still directly connected
                if current and current["next_hop"] == "0.0.0.0":
                    continue

            new_dist = rcv_dist + 1
            current = routing_table.get(subnet)

            print(f"\n[BF] {subnet} via {neighbor_ip} → {new_dist}")

            # MARK UNREACHABLE
            if new_dist >= INFINITY:
                if current and current["next_hop"] == neighbor_ip:
                    print(f"[UNREACHABLE] {subnet}")
                    routing_table[subnet]["distance"] = INFINITY
                    routing_table[subnet]["last_updated"] = time.time()
                    changed = True
                continue

            # ADD / UPDATE
            if current is None or new_dist < current["distance"]:
                routing_table[subnet] = {
                    "distance": new_dist,
                    "next_hop": neighbor_ip,
                    "last_updated": time.time()
                }
                install_kernel_route(subnet, neighbor_ip)
                print(f"[ADD] {subnet} via {neighbor_ip} dist={new_dist}")
                changed = True

            elif current["next_hop"] == neighbor_ip:
                routing_table[subnet]["last_updated"] = time.time()

    if changed:
        print_table()


def install_kernel_route(subnet, via_ip):
    os.system(f"ip route replace {subnet} via {via_ip} 2>/dev/null")

def expire_routes():
    while True:
        time.sleep(UPDATE_INTERVAL)
        now = time.time()

        with table_lock:
            for subnet, info in routing_table.items():
                if info["next_hop"] == "0.0.0.0":
                    continue

                if now - info["last_updated"] > ROUTE_TIMEOUT:
                    print(f"[EXPIRE] {subnet}")
                    routing_table[subnet]["distance"] = INFINITY

        print_table()


def print_table():
    print("\n" + "="*60)
    print(f"[ROUTING TABLE] {ROUTER_ID}")
    print(f"{'Subnet':<20} {'Dist':<5} {'Next Hop'}")
    print("-"*50)

    for subnet, info in routing_table.items():
        dist = "∞" if info["distance"] >= INFINITY else info["distance"]
        print(f"{subnet:<20} {dist:<5} {info['next_hop']}")

    print("="*60)

if __name__ == "__main__":
    init_routing_table()

    threading.Thread(target=broadcast_updates, daemon=True).start()
    threading.Thread(target=expire_routes, daemon=True).start()

    listen_for_updates()