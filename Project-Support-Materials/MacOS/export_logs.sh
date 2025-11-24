#!/bin/bash

OUTPUT_DIR=~/CTI_Pipeline/logs/collected
mkdir -p $OUTPUT_DIR

echo "Exporting osquery logs..."

# Export process events
osqueryi "SELECT * FROM process_events;" --json > $OUTPUT_DIR/process_events.json

# Export socket events
osqueryi "SELECT * FROM socket_events;" --json > $OUTPUT_DIR/socket_events.json

# Export file events
osqueryi "SELECT * FROM file_events;" --json > $OUTPUT_DIR/file_events.json

# Export running processes
osqueryi "SELECT * FROM processes;" --json > $OUTPUT_DIR/processes.json

# Export network connections
osqueryi "SELECT * FROM process_open_sockets;" --json > $OUTPUT_DIR/network_connections.json

# Export system info
osqueryi "SELECT * FROM system_info;" --json > $OUTPUT_DIR/system_info.json

# Count total events
total_events=0
for file in $OUTPUT_DIR/*.json; do
    count=$(jq '. | length' $file 2>/dev/null || echo 0)
    total_events=$((total_events + count))
    echo "$(basename $file): $count events"
done

echo ""
echo "✓ Total events exported: $total_events"
echo "✓ Location: $OUTPUT_DIR"
