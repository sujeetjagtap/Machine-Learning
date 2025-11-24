#!/usr/bin/env python3
"""
CTI Pipeline Validation Script for macOS
Validates all components of the pipeline
"""

import os
import pandas as pd
import numpy as np
import subprocess
import json
from pathlib import Path

def check_command(command):
    """Check if a command exists"""
    try:
        subprocess.run(command, capture_output=True, shell=True, timeout=5)
        return True
    except:
        return False

def validate_pipeline():
    """Comprehensive pipeline validation for macOS"""
    print("="*60)
    print("CTI PIPELINE VALIDATION (macOS)")
    print("="*60)
    
    base_path = Path.home() / "CTI_Pipeline"
    
    results = {
        'osquery_installed': False,
        'osquery_running': False,
        'logs_collected': False,
        'logs_parsed': False,
        'preprocessed': False,
        'embeddings_generated': False,
        'vectordb_populated': False,
        'events_labeled': False,
        'visualizations_created': False,
        'min_events_requirement': False
    }
    
    # 1. Check osquery installation
    print("\n[1/10] Checking osquery installation...")
    try:
        result = subprocess.run(['which', 'osqueryi'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            version_result = subprocess.run(['osqueryi', '--version'], 
                                          capture_output=True, text=True)
            print(f"  ✓ osquery is installed: {version_result.stdout.strip()}")
            results['osquery_installed'] = True
        else:
            print("  ✗ osquery not found")
            print("    Install with: brew install osquery")
    except Exception as e:
        print(f"  ✗ Could not verify osquery: {e}")
    
    # 2. Check if osquery daemon is running
    print("\n[2/10] Checking osquery daemon...")
    try:
        result = subprocess.run(['pgrep', '-x', 'osqueryd'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            pid = result.stdout.strip()
            print(f"  ✓ osqueryd is running (PID: {pid})")
            results['osquery_running'] = True
        else:
            print("  ✗ osqueryd is not running")
            print("    Start with: sudo osqueryd --config_path ~/CTI_Pipeline/osquery.conf &")
    except Exception as e:
        print(f"  ✗ Could not check osqueryd status: {e}")
    
    # 3. Check log collection
    print("\n[3/10] Checking log collection...")
    collected_dir = base_path / "logs" / "collected"
    if collected_dir.exists():
        json_files = list(collected_dir.glob("*.json"))
        if json_files:
            total_events = 0
            for json_file in json_files:
                try:
                    with open(json_file, 'r') as f:
                        data = json.load(f)
                        count = len(data) if isinstance(data, list) else 1
                        total_events += count
                        print(f"    - {json_file.name}: {count:,} events")
                except:
                    pass
            
            if total_events > 0:
                print(f"  ✓ Collected logs: {total_events:,} total events")
                results['logs_collected'] = True
            else:
                print("  ✗ Log files exist but contain no data")
        else:
            print("  ✗ No JSON log files found")
    else:
        print(f"  ✗ Collection directory not found: {collected_dir}")
        print("    Run: ./export_logs.sh")
    
    # 4. Check parsed logs
    print("\n[4/10] Checking parsed logs...")
    parsed_path = base_path / "logs" / "structured_events.csv"
    df_parsed = None
    if parsed_path.exists():
        try:
            df_parsed = pd.read_csv(parsed_path)
            print(f"  ✓ Parsed logs: {len(df_parsed):,} events")
            
            if 'event_type' in df_parsed.columns:
                print(f"    Event types distribution:")
                for event_type, count in df_parsed['event_type'].value_counts().items():
                    print(f"      - {event_type}: {count:,}")
            
            results['logs_parsed'] = True
        except Exception as e:
            print(f"  ✗ Error reading parsed logs: {e}")
    else:
        print(f"  ✗ Parsed logs not found: {parsed_path}")
        print("    Run: python3 parse_osquery_logs.py")
    
    # 5. Check preprocessed data
    print("\n[5/10] Checking preprocessed data...")
    preprocessed_path = base_path / "logs" / "preprocessed_events.csv"
    df_preprocessed = None
    if preprocessed_path.exists():
        try:
            df_preprocessed = pd.read_csv(preprocessed_path)
            print(f"  ✓ Preprocessed data: {len(df_preprocessed):,} events")
            
            if 'combined_text' in df_preprocessed.columns:
                non_empty = df_preprocessed['combined_text'].notna().sum()
                print(f"    - Non-empty combined_text: {non_empty:,}")
            
            results['preprocessed'] = True
        except Exception as e:
            print(f"  ✗ Error reading preprocessed data: {e}")
    else:
        print(f"  ✗ Preprocessed data not found: {preprocessed_path}")
        print("    Run: python3 preprocess_macos.py")
    
    # 6. Check embeddings
    print("\n[6/10] Checking embeddings...")
    embedding_path = base_path / "embeddings" / "event_embeddings.npy"
    embeddings = None
    if embedding_path.exists():
        try:
            embeddings = np.load(embedding_path)
            print(f"  ✓ Embeddings generated: {embeddings.shape[0]:,} vectors")
            print(f"    - Vector dimension: {embeddings.shape[1]}")
            print(f"    - Memory size: {embeddings.nbytes / 1024 / 1024:.2f} MB")
            results['embeddings_generated'] = True
        except Exception as e:
            print(f"  ✗ Error loading embeddings: {e}")
    else:
        print(f"  ✗ Embeddings not found: {embedding_path}")
        print("    Run: python3 generate_embeddings.py")
    
    # 7. Check vector database
    print("\n[7/10] Checking vector database...")
    vectordb_path = base_path / "vectordb"
    if vectordb_path.exists():
        try:
            import chromadb
            from chromadb.config import Settings
            
            client = chromadb.PersistentClient(
                path=str(vectordb_path),
                settings=Settings(anonymized_telemetry=False)
            )
            
            try:
                collection = client.get_collection("sysmon_events")
                count = collection.count()
                print(f"  ✓ Vector database populated: {count:,} vectors")
                
                # Test query
                test_results = collection.query(
                    query_texts=["bash"],
                    n_results=3
                )
                print(f"    - Test query successful: {len(test_results['documents'][0])} results returned")
                results['vectordb_populated'] = True
                
            except Exception as e:
                print(f"  ✗ Collection 'sysmon_events' not found: {e}")
                print("    Run: python3 setup_vectordb.py")
                
        except ImportError:
            print("  ✗ ChromaDB not installed")
            print("    Install with: pip3 install chromadb")
        except Exception as e:
            print(f"  ✗ Error accessing vector database: {e}")
    else:
        print(f"  ✗ Vector database directory not found: {vectordb_path}")
        print("    Run: python3 setup_vectordb.py")
    
    # 8. Check labels
    print("\n[8/10] Checking event labels...")
    labeled_path = base_path / "logs" / "labeled_events.csv"
    df_labeled = None
    if labeled_path.exists():
        try:
            df_labeled = pd.read_csv(labeled_path)
            label_counts = df_labeled['label'].value_counts()
            print(f"  ✓ Events labeled: {len(df_labeled):,} total")
            for label, count in label_counts.items():
                percentage = (count / len(df_labeled)) * 100
                print(f"    - {label.capitalize()}: {count:,} ({percentage:.1f}%)")
            
            results['events_labeled'] = True
            
            # Check for MITRE techniques
            if 'mitre_technique' in df_labeled.columns:
                malicious = df_labeled[df_labeled['mitre_technique'] != '']
                if len(malicious) > 0:
                    unique_techniques = malicious['mitre_technique'].nunique()
                    print(f"    - MITRE ATT&CK techniques detected: {unique_techniques}")
                    print(f"    - Top techniques:")
                    for tech, count in malicious['mitre_technique'].value_counts().head(5).items():
                        print(f"      • {tech}: {count} events")
        except Exception as e:
            print(f"  ✗ Error reading labeled events: {e}")
    else:
        print(f"  ✗ Labeled events not found: {labeled_path}")
        print("    Run: python3 label_events_macos.py")
    
    # 9. Check visualizations
    print("\n[9/10] Checking visualizations...")
    viz_dir = base_path / "visualizations"
    expected_viz = [
        'tsne_labeled_events.png',
        'tsne_mitre_techniques.png',
        'comprehensive_analysis.png',
        'embedding_quality_metrics.json'
    ]
    
    viz_count = 0
    if viz_dir.exists():
        for viz_file in expected_viz:
            path = viz_dir / viz_file
            if path.exists():
                size = path.stat().st_size / 1024  # KB
                print(f"    ✓ {viz_file} ({size:.1f} KB)")
                viz_count += 1
            else:
                print(f"    ✗ {viz_file} missing")
        
        if viz_count == len(expected_viz):
            print(f"  ✓ All visualizations created ({viz_count}/{len(expected_viz)})")
            results['visualizations_created'] = True
        else:
            print(f"  ⚠ Partial visualizations ({viz_count}/{len(expected_viz)})")
    else:
        print(f"  ✗ Visualizations directory not found: {viz_dir}")
    
    if viz_count == 0:
        print("    Run: python3 visualize_embeddings.py")
    
    # 10. Check minimum events requirement
    print("\n[10/10] Checking minimum events requirement...")
    if df_parsed is not None:
        if len(df_parsed) >= 10000:
            print(f"  ✓ Minimum requirement met: {len(df_parsed):,} >= 10,000 events")
            results['min_events_requirement'] = True
        else:
            deficit = 10000 - len(df_parsed)
            print(f"  ✗ Insufficient events: {len(df_parsed):,} < 10,000")
            print(f"    Need {deficit:,} more events")
            print("    Solutions:")
            print("      1. Run system for longer duration")
            print("      2. Generate more activity: ./generate_activity.sh")
            print("      3. Use public datasets (LANL, OpTC)")
    else:
        print("  ✗ Cannot check - parsed data not available")
    
    # Summary
    print("\n" + "="*60)
    print("VALIDATION SUMMARY")
    print("="*60)
    
    passed = sum(results.values())
    total = len(results)
    percentage = (passed / total) * 100
    
    print(f"\nTests Passed: {passed}/{total} ({percentage:.1f}%)\n")
    
    for test, result in results.items():
        status = "✓" if result else "✗"
        test_name = test.replace('_', ' ').title()
        color = '\033[0;32m' if result else '\033[0;31m'
        reset = '\033[0m'
        print(f"  {color}{status} {test_name}{reset}")
    
    # Overall status
    print("\n" + "="*60)
    if passed == total:
        print("\033[0;32m✓✓✓ PIPELINE FULLY OPERATIONAL ✓✓✓\033[0m")
        print("\nAll deliverables are complete and validated!")
        print("You can proceed with analysis and threat detection.")
        print("\nNext steps:")
        print("  1. Review visualizations: ~/CTI_Pipeline/visualizations/")
        print("  2. Query vector database for similar events")
        print("  3. Build ML models for threat detection")
    elif passed >= total * 0.75:
        print("\033[1;33m⚠ PIPELINE MOSTLY COMPLETE\033[0m")
        print("\nMost components are working. Address remaining issues:")
        for test, result in results.items():
            if not result:
                print(f"  - {test.replace('_', ' ').title()}")
    else:
        print("\033[0;31m✗ PIPELINE INCOMPLETE\033[0m")
        print("\nCritical components are missing. Please complete:")
        for test, result in results.items():
            if not result:
                print(f"  - {test.replace('_', ' ').title()}")
    
    print("="*60)
    
    # Save validation results
    results_path = base_path / "validation_results.json"
    try:
        with open(results_path, 'w') as f:
            json.dump({
                'timestamp': pd.Timestamp.now().isoformat(),
                'total_tests': total,
                'passed_tests': passed,
                'percentage': percentage,
                'results': results
            }, f, indent=2)
        print(f"\n✓ Validation results saved to: {results_path}")
    except Exception as e:
        print(f"\n⚠ Could not save validation results: {e}")
    
    return results

if __name__ == "__main__":
    try:
        validate_pipeline()
    except KeyboardInterrupt:
        print("\n\nValidation interrupted by user.")
    except Exception as e:
        print(f"\n\nUnexpected error during validation: {e}")
        import traceback
        traceback.print_exc()
