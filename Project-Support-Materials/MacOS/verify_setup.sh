#!/bin/bash

echo "=========================================="
echo "macOS CTI Pipeline Verification"
echo "=========================================="

# Check osquery
if command -v osqueryi &> /dev/null; then
    echo "✓ osquery is installed"
    osqueryi --version
else
    echo "✗ osquery not found"
fi

# Check if osqueryd is running
if pgrep osqueryd > /dev/null; then
    echo "✓ osqueryd daemon is running"
else
    echo "✗ osqueryd daemon not running"
fi

# Check logs directory
if [ -d ~/CTI_Pipeline/logs ]; then
    log_count=$(ls -1 ~/CTI_Pipeline/logs/*.log 2>/dev/null | wc -l)
    echo "✓ Logs directory exists ($log_count log files)"
else
    echo "✗ Logs directory not found"
fi

# Check recent events
echo ""
echo "Recent Process Events:"
osqueryi "SELECT COUNT(*) as count FROM process_events;" --json

echo ""
echo "Recent Socket Events:"
osqueryi "SELECT COUNT(*) as count FROM socket_events;" --json

echo "=========================================="
