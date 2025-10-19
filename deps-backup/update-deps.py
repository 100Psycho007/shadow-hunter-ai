#!/usr/bin/env python3
"""
Dependency management helper script for AI Threat Hunting Dashboard.

This script helps maintain reproducible dependency management using pip-tools.
"""

import subprocess
import sys
import os

def run_command(cmd, description):
    """Run a command and handle errors."""
    print(f"\n🔄 {description}...")
    try:
        result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed successfully")
        if result.stdout:
            print(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed:")
        print(e.stderr)
        return False

def main():
    """Main dependency management workflow."""
    print("🔧 AI Threat Hunting Dashboard - Dependency Management")
    print("=" * 60)
    
    # Check if pip-tools is installed
    try:
        subprocess.run(["pip-compile", "--version"], check=True, capture_output=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("❌ pip-tools not found. Installing...")
        if not run_command("pip install pip-tools", "Installing pip-tools"):
            sys.exit(1)
    
    # Check if requirements.in exists
    if not os.path.exists("requirements.in"):
        print("❌ requirements.in not found. Please create it first.")
        sys.exit(1)
    
    # Compile requirements
    if not run_command("pip-compile requirements.in", "Compiling requirements.in to requirements.txt"):
        sys.exit(1)
    
    # Optional: Install updated requirements
    install = input("\n📦 Install updated requirements? (y/N): ").lower().strip()
    if install == 'y':
        if not run_command("pip install -r requirements.txt", "Installing updated requirements"):
            sys.exit(1)
    
    print("\n✅ Dependency management completed!")
    print("\n📋 Next steps:")
    print("1. Review the updated requirements.txt")
    print("2. Test your application with the new dependencies")
    print("3. Commit both requirements.in and requirements.txt")

if __name__ == "__main__":
    main()