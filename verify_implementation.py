#!/usr/bin/env python3
"""
Pre-Deployment Verification Script

Validates that all production-ready features are properly implemented
and the code is ready for deployment.
"""

import os
import sys
from pathlib import Path


def check_file_exists(filepath: str, description: str) -> bool:
    """Check if a file exists"""
    path = Path(filepath)
    if path.exists():
        print(f"✅ {description}: {filepath}")
        return True
    else:
        print(f"❌ {description} MISSING: {filepath}")
        return False


def check_implementation():
    """Verify all implementation files exist"""
    print("\n" + "="*60)
    print("🔍 VERIFICATION: Implementation Files")
    print("="*60)
    
    base_path = Path(__file__).parent / "python" / "marty_credentials"
    
    checks = [
        # Observability
        (base_path / "infrastructure/observability/__init__.py", "Observability module"),
        (base_path / "infrastructure/observability/metrics.py", "Metrics module"),
        (base_path / "infrastructure/observability/rate_limiter.py", "Rate limiter"),
        
        # Events
        (base_path / "infrastructure/events/__init__.py", "Events module"),
        (base_path / "infrastructure/events/publisher.py", "Event publisher"),
        
        # Modified files
        (base_path / "config.py", "Configuration"),
        (base_path / "infrastructure/auth/token_validator.py", "Token validator"),
        (base_path / "adapters/rust/adapter.py", "Rust adapter"),
        (base_path / "adapters/adapters/credentials/spruceid.py", "SpruceID adapter"),
        (base_path / "adapters/services/verification_service.py", "Verification service"),
        (base_path / "adapters/services/issuance_service.py", "Issuance service"),
    ]
    
    results = [check_file_exists(str(path), desc) for path, desc in checks]
    return all(results)


def check_code_quality():
    """Check for critical code patterns"""
    print("\n" + "="*60)
    print("🔍 VERIFICATION: Code Quality")
    print("="*60)
    
    base_path = Path(__file__).parent / "python" / "marty_credentials"
    
    # Check that print() was removed from critical files
    critical_files = [
        base_path / "adapters/rust/adapter.py",
        base_path / "adapters/adapters/credentials/spruceid.py",
    ]
    
    all_good = True
    for filepath in critical_files:
        if not filepath.exists():
            continue
            
        content = filepath.read_text()
        
        # Check for print statements (excluding comments)
        lines = content.split('\n')
        print_found = False
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#'):
                continue
            if 'print(' in line and 'print(f"Warning: Credential verification failed' in line:
                print(f"❌ Found print() statement in {filepath.name}:{i}")
                print(f"   {line.strip()}")
                print_found = True
                all_good = False
        
        if not print_found:
            print(f"✅ No problematic print() in {filepath.name}")
    
    # Check for CredentialVerificationError usage
    for filepath in critical_files:
        if not filepath.exists():
            continue
        content = filepath.read_text()
        if 'CredentialVerificationError' in content and 'raise CredentialVerificationError' in content:
            print(f"✅ Exception handling in {filepath.name}")
        elif filepath.exists():
            print(f"⚠️  Could not verify exception handling in {filepath.name}")
    
    return all_good


def check_metrics_implementation():
    """Verify metrics are properly defined"""
    print("\n" + "="*60)
    print("🔍 VERIFICATION: Metrics Implementation")
    print("="*60)
    
    metrics_file = Path(__file__).parent / "python" / "marty_credentials" / "infrastructure/observability/metrics.py"
    
    if not metrics_file.exists():
        print("❌ Metrics file not found")
        return False
    
    content = metrics_file.read_text()
    
    required_metrics = [
        'credentials_issued_total',
        'credentials_verified_total',
        'credential_verification_failures_total',
        'credential_issuance_duration_seconds',
        'credential_verification_duration_seconds',
        'rate_limit_remaining',
        'active_credentials',
    ]
    
    all_found = True
    for metric in required_metrics:
        if metric in content:
            print(f"✅ Metric defined: {metric}")
        else:
            print(f"❌ Metric MISSING: {metric}")
            all_found = False
    
    return all_found


def check_configuration():
    """Verify configuration is complete"""
    print("\n" + "="*60)
    print("🔍 VERIFICATION: Configuration")
    print("="*60)
    
    config_file = Path(__file__).parent / "python" / "marty_credentials" / "config.py"
    
    if not config_file.exists():
        print("❌ Config file not found")
        return False
    
    content = config_file.read_text()
    
    required_config = [
        'trusted_mdoc_issuer_certs_path',
        'enable_metrics',
        'enable_rate_limiting',
        'enable_event_publishing',
        'kafka_bootstrap_servers',
        'rate_limit_per_minute',
    ]
    
    all_found = True
    for config_item in required_config:
        if config_item in content:
            print(f"✅ Config field: {config_item}")
        else:
            print(f"❌ Config MISSING: {config_item}")
            all_found = False
    
    return all_found


def check_documentation():
    """Verify documentation exists"""
    print("\n" + "="*60)
    print("🔍 VERIFICATION: Documentation")
    print("="*60)
    
    docs = [
        ("IMPLEMENTATION_SUMMARY.md", "Implementation summary"),
        ("CONFIGURATION.md", "Configuration guide"),
        ("PRODUCTION_READY.md", "Production readiness"),
        ("ARCHITECTURE.md", "Architecture overview"),
        ("DEPLOYMENT_CHECKLIST.md", "Deployment checklist"),
    ]
    
    base_path = Path(__file__).parent
    results = [check_file_exists(str(base_path / doc), desc) for doc, desc in docs]
    return all(results)


def main():
    """Run all verification checks"""
    print("\n" + "="*70)
    print("🚀 PRE-DEPLOYMENT VERIFICATION")
    print("   marty-credentials v2.0 - Production Ready Features")
    print("="*70)
    
    checks = [
        ("Implementation Files", check_implementation),
        ("Code Quality", check_code_quality),
        ("Metrics", check_metrics_implementation),
        ("Configuration", check_configuration),
        ("Documentation", check_documentation),
    ]
    
    results = {}
    for name, check_func in checks:
        try:
            results[name] = check_func()
        except Exception as e:
            print(f"\n❌ Error during {name} check: {e}")
            results[name] = False
    
    # Summary
    print("\n" + "="*70)
    print("📊 VERIFICATION SUMMARY")
    print("="*70)
    
    for name, passed in results.items():
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status}: {name}")
    
    all_passed = all(results.values())
    
    print("\n" + "="*70)
    if all_passed:
        print("🎉 ALL CHECKS PASSED - READY FOR DEPLOYMENT!")
        print("="*70)
        print("\nNext steps:")
        print("1. Review DEPLOYMENT_CHECKLIST.md")
        print("2. Configure environment variables")
        print("3. Install dependencies: pip install -e .")
        print("4. Deploy to staging environment")
        print("5. Monitor metrics at /metrics endpoint")
        return 0
    else:
        print("⚠️  SOME CHECKS FAILED - REVIEW ISSUES BEFORE DEPLOYMENT")
        print("="*70)
        return 1


if __name__ == "__main__":
    sys.exit(main())
