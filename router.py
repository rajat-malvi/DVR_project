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

# Event to trigger an immediate broadcast when routes change
trigger_update    = threading.Event()

def init_routing_table():
    global local_subnets_set

    # Retry subnet detection — Docker attaches secondary interfaces
    # slightly after container start, so the first scan may be incomplete.
    # Keep polling until the subnet list is stable for 2 consecutive checks.
    subnets = []
    stable_count = 0
    for attempt in range(15):
        time.sleep(1)
        new_subnets = get_local_subnets()
        if new_subnets == subnets and new_subnets:
            stable_count += 1
            if stable_count >= 2:
                print(f"[INIT] Subnet list stable at attempt {attempt+1}: {subnets}")
                break
        else:
            stable_count = 0
            subnets = new_subnets
        print(f"[INIT] Attempt {attempt+1}: found {len(subnets)} subnet(s): {subnets}")

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
    except Exception:
        print("[WARN] Could not detect subnets")
    return list(set(subnets))


# PERIODIC RESCAN — picks up interfaces Docker attaches/detaches after startup
def rescan_local_subnets():
    global local_subnets_set
    while True:
        time.sleep(UPDATE_INTERVAL)
        current_subnets = set(get_local_subnets())
        
        # Detect new interfaces
        new_ones = current_subnets - local_subnets_set
        # Detect removed interfaces
        removed_ones = local_subnets_set - current_subnets
        
        changed = False
        
        if new_ones:
            print(f"[RESCAN] Discovered new local subnets: {new_ones}")
            with table_lock:
                for subnet in new_ones:
                    routing_table[subnet] = {
                        "distance": 0,
                        "next_hop": "0.0.0.0",
                        "last_updated": time.time()
                    }
            changed = True
        
        if removed_ones:
            print(f"[RESCAN] Lost local subnets: {removed_ones}")
            with table_lock:
                for subnet in removed_ones:
                    if subnet in routing_table:
                        # Mark as unreachable
                        routing_table[subnet]["distance"] = INFINITY
                        routing_table[subnet]["next_hop"] = "0.0.0.0"
                        routing_table[subnet]["last_updated"] = time.time()
            changed = True
        
        if changed:
            local_subnets_set = current_subnets
            print_table()
            trigger_update.set()


def addr_to_network(addr_prefix):
    try:
        ip_str, prefix = addr_prefix.split("/")
        prefix = int(prefix)
        ip_parts = list(map(int, ip_str.split(".")))
        mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        net = [(ip_parts[i] & ((mask >> (24 - 8 * i)) & 0xFF)) for i in range(4)]
        return f"{net[0]}.{net[1]}.{net[2]}.{net[3]}/{prefix}"
    except Exception:
        return None


# BUILD UPDATE PACKET for a specific neighbor (split horizon + poison reverse)
def build_packet_for(neighbor_ip, snapshot):
    routes = []
    for subnet, info in snapshot.items():
        # Poison reverse: if we learned this route VIA this neighbor,
        # advertise it back as INFINITY so they don't loop through us.
        if info["next_hop"] == neighbor_ip:
            dist = INFINITY
        else:
            dist = info["distance"]
        routes.append({"subnet": subnet, "distance": dist})
    return {
        "router_id": MY_IP,
        "version": PROTOCOL_VERSION,
        "routes": routes
    }


# BROADCAST — sends on timer OR when trigger_update is set
def broadcast_updates():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    while True:
        # Wait up to UPDATE_INTERVAL seconds, or fire immediately on trigger
        triggered = trigger_update.wait(timeout=UPDATE_INTERVAL)
        trigger_update.clear()

        with table_lock:
            snapshot = dict(routing_table)

        for neighbor_ip in NEIGHBORS:
            packet = build_packet_for(neighbor_ip, snapshot)
            print(f"\n[SENDING UPDATE] To {neighbor_ip} (triggered={triggered})")
            pp.pprint(packet)
            try:
                sock.sendto(json.dumps(packet).encode(), (neighbor_ip, PORT))
            except Exception:
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

        except Exception as e:
            print(f"[ERROR] Receiving: {e}")


# BELLMAN-FORD — fixed to handle poison reverse and triggered updates
def update_logic(neighbor_ip, routes):
    changed = False

    with table_lock:
        for route in routes:
            subnet = route.get("subnet")
            rcv_dist = route.get("distance")

            if not subnet or rcv_dist is None:
                continue

            # Never overwrite our own directly-connected subnets
            if subnet in local_subnets_set:
                current = routing_table.get(subnet)
                if current and current["next_hop"] == "0.0.0.0":
                    continue

            new_dist = min(rcv_dist + 1, INFINITY)
            current = routing_table.get(subnet)

            print(f"\n[BF] {subnet} via {neighbor_ip} → new_dist={new_dist}")

            if new_dist >= INFINITY:
                # Process poison: if we were routing through this neighbor,
                # mark route as unreachable (don't skip it!)
                if current and current["next_hop"] == neighbor_ip and current["distance"] < INFINITY:
                    print(f"[POISON] {subnet} via {neighbor_ip} marked INFINITY")
                    routing_table[subnet]["distance"] = INFINITY
                    routing_table[subnet]["last_updated"] = time.time()
                    changed = True
                continue

            # ADD new route
            if current is None:
                routing_table[subnet] = {
                    "distance": new_dist,
                    "next_hop": neighbor_ip,
                    "last_updated": time.time()
                }
                install_kernel_route(subnet, neighbor_ip)
                print(f"[ADD] {subnet} via {neighbor_ip} dist={new_dist}")
                changed = True

            # UPDATE: better path found
            elif new_dist < current["distance"]:
                routing_table[subnet] = {
                    "distance": new_dist,
                    "next_hop": neighbor_ip,
                    "last_updated": time.time()
                }
                install_kernel_route(subnet, neighbor_ip)
                print(f"[UPDATE] {subnet} via {neighbor_ip} dist={new_dist} (was {current['distance']})")
                changed = True

            #same neighbor, same distance — just update timestamp
            elif current["next_hop"] == neighbor_ip:
                routing_table[subnet]["last_updated"] = time.time()

            # EQUAL-COST alternative via different neighbor — accept to allow failover
            elif new_dist == current["distance"] and current["next_hop"] != neighbor_ip:
                # Keep existing path but refresh timestamp to prevent expiry
                routing_table[subnet]["last_updated"] = time.time()

    if changed:
        print_table()
        # Trigger an immediate update so neighbors learn changes quickly
        trigger_update.set()


def install_kernel_route(subnet, via_ip):
    os.system(f"ip route replace {subnet} via {via_ip} 2>/dev/null")


def expire_routes():
    while True:
        time.sleep(UPDATE_INTERVAL)
        now = time.time()
        changed = False

        with table_lock:
            for subnet, info in list(routing_table.items()):
                # Never expire directly-connected routes
                if info["next_hop"] == "0.0.0.0":
                    continue
                # Already marked infinite — nothing to do
                if info["distance"] >= INFINITY:
                    continue

                if now - info["last_updated"] > ROUTE_TIMEOUT:
                    print(f"[EXPIRE] {subnet} — no update in {ROUTE_TIMEOUT}s")
                    routing_table[subnet]["distance"] = INFINITY
                    changed = True

        if changed:
            print_table()
            trigger_update.set()


def print_table():
    print("\n" + "=" * 60)
    print(f"[ROUTING TABLE] {ROUTER_ID}")
    print(f"{'Subnet':<20} {'Dist':<5} {'Next Hop'}")
    print("-" * 50)
    for subnet, info in routing_table.items():
        dist = "∞" if info["distance"] >= INFINITY else info["distance"]
        print(f"{subnet:<20} {dist:<5} {info['next_hop']}")
    print("=" * 60)


if __name__ == "__main__":
    init_routing_table()
    # Send an initial update immediately so neighbors learn our subnets fast
    trigger_update.set()

    threading.Thread(target=broadcast_updates, daemon=True).start()
    threading.Thread(target=expire_routes, daemon=True).start()
    threading.Thread(target=rescan_local_subnets, daemon=True).start()

    listen_for_updates()