#!/bin/bash

echo "=========================================="
echo "CTI Pipeline Setup for macOS"
echo "=========================================="

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Step 1: Install dependencies
echo -e "\n${YELLOW}[1/8] Installing dependencies...${NC}"
if ! command -v brew &> /dev/null; then
    echo "Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi

brew install osquery python@3.11 jq

# Install Python packages
pip3 install pandas numpy sentence-transformers chromadb scikit-learn matplotlib seaborn

echo -e "${GREEN}✓ Dependencies installed${NC}"

# Step 2: Setup directories
echo -e "\n${YELLOW}[2/8] Creating directory structure...${NC}"
cd ~/CTI_Pipeline
mkdir -p logs/collected embeddings models vectordb visualizations

echo -e "${GREEN}✓ Directories created${NC}"

# Step 3: Configure osquery
echo -e "\n${YELLOW}[3/8] Configuring osquery...${NC}"
# (osquery.conf already created in Part 1)

echo -e "${GREEN}✓ osquery configured${NC}"

# Step 4: Start osquery
echo -e "\n${YELLOW}[4/8] Starting osquery daemon...${NC}"
sudo osqueryd \
  --config_path ~/CTI_Pipeline/osquery.conf \
  --pidfile /var/run/osqueryd.pid \
  --database_path ~/CTI_Pipeline/osquery.db \
  --logger_path ~/CTI_Pipeline/logs &

sleep 5
echo -e "${GREEN}✓ osquery started${NC}"

# Step 5: Generate activity
echo -e "\n${YELLOW}[5/8] Generating system activity...${NC}"
./generate_activity.sh

echo -e "${GREEN}✓ Activity generated${NC}"

# Step 6: Export logs
echo -e "\n${YELLOW}[6/8] Exporting logs...${NC}"
./export_logs.sh

echo -e "${GREEN}✓ Logs exported${NC}"

# Step 7: Process data
echo -e "\n${YELLOW}[7/8] Processing data pipeline...${NC}"
python3 parse_osquery_logs.py
python3 preprocess_macos.py
python3 generate_embeddings.py
python3 setup_vectordb.py
python3 label_events_macos.py

echo -e "${GREEN}✓ Data processed${NC}"

# Step 8: Generate visualizations
echo -e "\n${YELLOW}[8/8] Generating visualizations...${NC}"
python3 visualize_embeddings.py

echo -e "${GREEN}✓ Visualizations generated${NC}"

# Final summary
echo -e "\n=========================================="
echo -e "${GREEN}✓✓✓ Pipeline Setup Complete! ✓✓✓${NC}"
echo "=========================================="
echo ""
echo "Next steps:"
echo "  1. Review logs: ~/CTI_Pipeline/logs/"
echo "  2. Check visualizations: ~/CTI_Pipeline/visualizations/"
echo "  3. Validate: python3 validate_pipeline.py"
echo ""
