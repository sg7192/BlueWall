import asyncio
import json
import socket
import random
import argparse
import uuid
from bleak import BleakScanner

TCP_HOST = "127.0.0.1"
TCP_PORT = 9001
BATCH_INTERVAL = 15  # seconds
BATCHES_PER_MINUTE = 4

SIM_MANUFACTURER_KEY = 0xFFFF
SIM_MANUFACTURER_HEX = "deadbeef33445566778899aabbccddeeff112233"
SIM_UUID = "f000aaaa-0451-4000-b000-000000000000"  # Custom spoof UUID


def parse_args():
    parser = argparse.ArgumentParser(description="BLE relay with spoofing modes")
    parser.add_argument(
        "--mode",
        choices=["mac_randomization", "uuid_spoofing", "beacon_flooding", "demo"],
        required=True,
        help="Spoofing mode to activate",
    )
    return parser.parse_args()


def generate_spoofed_devices(mode, count=7):
    spoofed = []
    for i in range(count):
        mac = f"02:11:22:33:{i//256:02X}:{i%256:02X}"
        device = {
            "name": "SpoofedDevice",
            "address": mac,
            "rssi": -random.randint(40, 90),
            "timestamp": int(asyncio.get_event_loop().time() * 1000),
            "spoofed": True
        }
        if mode == "mac_randomization":
            device["manufacturerHex"] = SIM_MANUFACTURER_HEX
        elif mode == "uuid_spoofing":
            # random_uuid = str(uuid.uuid4())  # Unique UUID per spoofed device
            device["serviceUUIDs"] = [SIM_UUID]
        spoofed.append(device)
    return spoofed


def generate_beacon_flood_from_real(real_entry, flood_count=6000):
    if not real_entry:
        print("[!] No real advertisement to base flood on.")
        return []

    spoofed_list = []
    now = int(asyncio.get_event_loop().time() * 1000)
    for i in range(flood_count):
        clone = dict(real_entry)
        clone["timestamp"] = now + i
        clone["spoofed"] = True
        spoofed_list.append(clone)

    return spoofed_list


async def scan_and_relay(mode):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((TCP_HOST, TCP_PORT))
        server_socket.listen(1)
        print(f"[+] Waiting for AVD connection on port {TCP_PORT}...")
        client_socket, addr = server_socket.accept()
        print(f"[+] AVD connected from {addr}")

        results = {}

        def detection_callback(device, advertisement_data):
            entry = {
                "name": device.name or "Unknown",
                "address": device.address,
                "rssi": advertisement_data.rssi,
                "timestamp": int(asyncio.get_event_loop().time() * 1000),
            }

            md = advertisement_data.manufacturer_data or {}
            if SIM_MANUFACTURER_KEY in md:
                entry["manufacturerHex"] = md[SIM_MANUFACTURER_KEY].hex().lower()

            if advertisement_data.service_uuids:
                entry["serviceUUIDs"] = advertisement_data.service_uuids

            results[device.address] = entry

        scanner = BleakScanner(detection_callback, scanning_mode="active")

        spoof_modes = ["mac_randomization", "uuid_spoofing", "beacon_flooding"]
        current_demo_index = 0
        batch_count = 0
        spoof_mode = mode

        async with scanner:
            while True:
                await asyncio.sleep(BATCH_INTERVAL)
                batch_count += 1

                # In demo mode, switch spoofing mode every 4 batches (1 minute)
                if mode == "demo" and (batch_count - 1) % BATCHES_PER_MINUTE == 0:
                    spoof_mode = spoof_modes[current_demo_index]
                    print(f"\n[DEMO] >>> Switching to mode: {spoof_mode.upper()} <<<")
                    current_demo_index = (current_demo_index + 1) % len(spoof_modes)

                devices_list = list(results.values())
                results.clear()

                # Inject spoofed devices
                if spoof_mode in ["mac_randomization", "uuid_spoofing"] and (batch_count % BATCHES_PER_MINUTE == 0):
                    spoofed = generate_spoofed_devices(spoof_mode)
                    devices_list.extend(spoofed)
                    print(f"[+] Injected {len(spoofed)} spoofed devices ({spoof_mode})")

                # Inject beacon flood
                if spoof_mode == "beacon_flooding" and (batch_count % BATCHES_PER_MINUTE == 0):
                    if devices_list:
                        real_sample = random.choice(devices_list)
                        flood_batch = generate_beacon_flood_from_real(real_sample)
                        devices_list.extend(flood_batch)
                        print(f"[+] Injected {len(flood_batch)} beacon flood entries from {real_sample['address']}")
                    else:
                        print("[!] Skipping beacon flood - no real device found to copy")

                if devices_list:
                    json_data = json.dumps(devices_list) + "\n"
                    try:
                        client_socket.sendall(json_data.encode("utf-8"))
                        print(f"[✓] Sent {len(devices_list)} devices to AVD")
                    except Exception as e:
                        print(f"[!] Error sending to AVD: {e}")
                        break
                else:
                    print("[!] No devices found this batch")


if __name__ == "__main__":
    args = parse_args()
    asyncio.run(scan_and_relay(args.mode))

