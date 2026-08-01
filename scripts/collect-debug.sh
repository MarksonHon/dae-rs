#!/bin/bash
set -e

LOG="/tmp/dae-rs-debug.log"
DAE_RS_BIN="./target/debug/dae-rs"
DAE_RS_CONFIG="config-example/config-minimal.daefile"
PID_FILE="/tmp/dae-rs.pid"
NETNS_NAME="dae-rs"
NETNS_PATH="/var/run/netns/${NETNS_NAME}"
RUST_LOG=debug
export RUST_LOG

echo "=== dae-rs Debug Collection Script ===" > "$LOG"
echo "Start time: $(date)" >> "$LOG"

# Helper: find bpf map ID by name prefix
find_map_id() {
    local pattern="$1"
    bpftool map show 2>/dev/null | grep "$pattern" | awk '{print $1}' | tr -d ':'
}

# Cleanup function - called on exit to ensure dae-rs is stopped and diagnostics are collected
cleanup() {
    echo "" >> "$LOG"
    echo "=== Stopping dae-rs ===" >> "$LOG"

    # Collect diagnostics BEFORE killing dae-rs so BPF state is still live
    DEBUG_MAP_ID=$(find_map_id "debug_counter_m")
    if [ -n "$DEBUG_MAP_ID" ]; then
        echo "" >> "$LOG"
        echo "=== Debug Counter Map (id $DEBUG_MAP_ID) ===" >> "$LOG"
        bpftool map dump id $DEBUG_MAP_ID >> "$LOG" 2>&1 || echo "Failed to dump debug_counter_map" >> "$LOG"
    fi

    SOCK_MAP_ID=$(find_map_id "listen_socket_m")
    if [ -n "$SOCK_MAP_ID" ]; then
        echo "" >> "$LOG"
        echo "=== Listen Socket Map (id $SOCK_MAP_ID) ===" >> "$LOG"
        bpftool map dump id $SOCK_MAP_ID >> "$LOG" 2>&1 || echo "Failed to dump listen_socket_map" >> "$LOG"
    fi

    echo "" >> "$LOG"
    echo "=== BPF Programs ===" >> "$LOG"
    bpftool prog show 2>&1 | grep -E "tproxy|dae" >> "$LOG" 2>&1 || echo "Failed to show programs" >> "$LOG"

    echo "" >> "$LOG"
    echo "=== Socket Listening State ===" >> "$LOG"
    ss -tlnp >> "$LOG" 2>&1 || echo "Failed to show sockets" >> "$LOG"

    # Capture proxy namespace state while dae-rs is still running
    if [ -S "$NETNS_PATH" ] || ip netns list 2>/dev/null | grep -q "$NETNS_NAME"; then
        echo "" >> "$LOG"
        echo "=== Proxy NS listening sockets ===" >> "$LOG"
        ip netns exec "$NETNS_NAME" ss -tulnp >> "$LOG" 2>&1 || echo "Failed to show proxy NS sockets" >> "$LOG"

        echo "" >> "$LOG"
        echo "=== Proxy NS tcpdump (SYN packets) ===" >> "$LOG"
        timeout 3 ip netns exec "$NETNS_NAME" tcpdump -i any -n 'tcp[tcpflags] & tcp-syn != 0' -c 20 >> "$LOG" 2>&1 || echo "tcpdump not available or timeout" >> "$LOG"

        echo "" >> "$LOG"
        echo "=== Proxy NS loopback tcpdump (TCP) ===" >> "$LOG"
        timeout 3 ip netns exec "$NETNS_NAME" tcpdump -i lo -n 'tcp' -c 20 >> "$LOG" 2>&1 || echo "lo tcpdump not available or timeout" >> "$LOG"

        echo "" >> "$LOG"
        echo "=== Proxy NS interfaces ===" >> "$LOG"
        ip netns exec "$NETNS_NAME" ip addr >> "$LOG" 2>&1 || echo "Failed to list interfaces" >> "$LOG"

        echo "" >> "$LOG"
        echo "=== Proxy NS routes ===" >> "$LOG"
        ip netns exec "$NETNS_NAME" ip rule list >> "$LOG" 2>&1 || echo "Failed to list rules" >> "$LOG"
        ip netns exec "$NETNS_NAME" ip route show table 2023 >> "$LOG" 2>&1 || echo "Failed to show routes" >> "$LOG"
    fi

    # Now stop dae-rs
    if [ -f "$PID_FILE" ]; then
        kill $(cat "$PID_FILE") 2>/dev/null || true
        rm -f "$PID_FILE"
    fi
    pkill -f "dae-rs" 2>/dev/null || true
    sleep 2

    echo "" >> "$LOG"
    echo "=== dmesg (last 30 lines, kernel BPF messages) ===" >> "$LOG"
    dmesg | tail -30 >> "$LOG" 2>&1 || echo "dmesg not available" >> "$LOG"

    echo "" >> "$LOG"
    echo "End time: $(date)" >> "$LOG"
    echo "=== Debug collection complete ===" >> "$LOG"
    echo "Output saved to: $LOG"
}

trap cleanup EXIT

# Start dae-rs
echo "Starting dae-rs..."
$DAE_RS_BIN run -c "$DAE_RS_CONFIG" > /tmp/dae-rs.log 2>&1 &
echo $! > "$PID_FILE"
echo "dae-rs started with PID $(cat $PID_FILE)"

# Wait for startup
echo "Waiting 5 seconds for dae-rs to start..."
sleep 5

# Pre-traffic snapshot
echo "" >> "$LOG"
echo "=== Pre-traffic Debug Counter Map ===" >> "$LOG"
DEBUG_MAP_ID=$(find_map_id "debug_counter_m")
if [ -n "$DEBUG_MAP_ID" ]; then
    bpftool map dump id $DEBUG_MAP_ID >> "$LOG" 2>&1 || echo "Failed" >> "$LOG"
else
    echo "debug_counter_map not found" >> "$LOG"
fi

echo "" >> "$LOG"
echo "=== Pre-traffic Listen Socket Map ===" >> "$LOG"
SOCK_MAP_ID=$(find_map_id "listen_socket_m")
if [ -n "$SOCK_MAP_ID" ]; then
    bpftool map dump id $SOCK_MAP_ID >> "$LOG" 2>&1 || echo "Failed" >> "$LOG"
else
    echo "listen_socket_map not found" >> "$LOG"
fi

# Generate test traffic
echo "Generating test traffic..."
curl -s -o /dev/null -w "curl google.com: %{http_code}\n" --connect-timeout 5 https://www.google.com >> "$LOG" 2>&1 || echo "curl google.com failed" >> "$LOG"
curl -s -o /dev/null -w "curl baidu.com: %{http_code}\n" --connect-timeout 5 https://www.baidu.com >> "$LOG" 2>&1 || echo "curl baidu.com failed" >> "$LOG"
curl -s -o /dev/null -w "curl example.com: %{http_code}\n" --connect-timeout 5 https://example.com >> "$LOG" 2>&1 || echo "curl example.com failed" >> "$LOG"

# Direct IP probes (bypass DNS) to distinguish DNS-path failures from TCP datapath failures
curl -k -s -o /dev/null -w "curl 1.1.1.1: %{http_code}\n" --connect-timeout 5 https://1.1.1.1 >> "$LOG" 2>&1 || echo "curl 1.1.1.1 failed" >> "$LOG"
curl -k -s -o /dev/null -w "curl 8.8.8.8: %{http_code}\n" --connect-timeout 5 https://8.8.8.8 >> "$LOG" 2>&1 || echo "curl 8.8.8.8 failed" >> "$LOG"

# Wait for traffic processing
echo "Waiting 10 seconds for traffic processing..."
sleep 10

# Post-traffic snapshot
echo "" >> "$LOG"
echo "=== Post-traffic Debug Counter Map ===" >> "$LOG"
DEBUG_MAP_ID=$(find_map_id "debug_counter_m")
if [ -n "$DEBUG_MAP_ID" ]; then
    bpftool map dump id $DEBUG_MAP_ID >> "$LOG" 2>&1 || echo "Failed" >> "$LOG"
else
    echo "debug_counter_map not found" >> "$LOG"
fi

echo "" >> "$LOG"
echo "=== Post-traffic Listen Socket Map ===" >> "$LOG"
SOCK_MAP_ID=$(find_map_id "listen_socket_m")
if [ -n "$SOCK_MAP_ID" ]; then
    bpftool map dump id $SOCK_MAP_ID >> "$LOG" 2>&1 || echo "Failed" >> "$LOG"
else
    echo "listen_socket_map not found" >> "$LOG"
fi

# Generate more traffic
curl -s -o /dev/null -w "curl github.com: %{http_code}\n" --connect-timeout 5 https://github.com >> "$LOG" 2>&1 || echo "curl github.com failed" >> "$LOG"
curl -s -o /dev/null -w "curl cloudflare.com: %{http_code}\n" --connect-timeout 5 https://www.cloudflare.com >> "$LOG" 2>&1 || echo "curl cloudflare.com failed" >> "$LOG"
curl -k -s -o /dev/null -w "curl 9.9.9.9: %{http_code}\n" --connect-timeout 5 https://9.9.9.9 >> "$LOG" 2>&1 || echo "curl 9.9.9.9 failed" >> "$LOG"

sleep 5

echo "" >> "$LOG"
echo "=== Final Debug Counter Map ===" >> "$LOG"
DEBUG_MAP_ID=$(find_map_id "debug_counter_m")
if [ -n "$DEBUG_MAP_ID" ]; then
    bpftool map dump id $DEBUG_MAP_ID >> "$LOG" 2>&1 || echo "Failed" >> "$LOG"
else
    echo "debug_counter_map not found" >> "$LOG"
fi

echo "" >> "$LOG"
echo "=== Final Listen Socket Map ===" >> "$LOG"
SOCK_MAP_ID=$(find_map_id "listen_socket_m")
if [ -n "$SOCK_MAP_ID" ]; then
    bpftool map dump id $SOCK_MAP_ID >> "$LOG" 2>&1 || echo "Failed" >> "$LOG"
else
    echo "listen_socket_map not found" >> "$LOG"
fi

echo "Debug collection complete. Output in $LOG"
