#!/bin/bash
# CryptoBench Pro - Java Build Script
# This script compiles the Java encryption implementations

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/../../.." &> /dev/null && pwd )"

echo "Building Java encryption implementations..."

# Download json-simple if not already present
JSON_SIMPLE_JAR="$SCRIPT_DIR/json-simple-1.1.1.jar"
if [ ! -f "$JSON_SIMPLE_JAR" ]; then
    echo "Downloading json-simple library..."
    curl -L "https://repo1.maven.org/maven2/com/googlecode/json-simple/json-simple/1.1.1/json-simple-1.1.1.jar" -o "$JSON_SIMPLE_JAR"
fi

# Compile Java sources
javac -cp "$JSON_SIMPLE_JAR" "$SCRIPT_DIR/JavaCore.java"

# Check compilation result
if [ $? -eq 0 ]; then
    echo "Java compilation completed successfully"
    exit 0
else
    echo "Java compilation failed"
    exit 1
fi 